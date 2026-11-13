#!/usr/bin/env python3
"""Audio-manipulation steganography axis (wave 3, ticket C8). Offline, pure Python (standard
library; carve_stego's offline DTMF reader when numpy is present, else its own Goertzel).

The offline stego battery reads spatial LSB, DTMF and Morse, but not the "listen differently" axis:
audio whose payload only appears REVERSED (backmasked), in the LEFT-minus-RIGHT stereo difference,
at half speed, or in the sample LSBs of a non-WAV PCM container (AIFF). This module produces those
transformed recordings as CANDIDATES to feed the existing spectrogram / SSTV / DTMF tools.

Never-wrong: everything here is UNSURE only. A reverse is a deterministic, self-checking operation
(re-reversing round-trips), but WHICH transform the author intended is the author's choice, not a
fact in the bytes, so even a DTMF string decoded from the reversed channel is offered as a candidate
(`labels.candidates` / render_candidates), never plain. The transformed WAV bytes are handed to the
sandbox spectrogram/SSTV reader (stego_tools) or to carve_stego.dtmf off the clock. The flag is
never used or submitted.

  wav_channels(data) -> (info, [per-channel int samples]) | None   PCM WAV, 8/16/24/32-bit
  aiff_samples(data) -> (rate, bits, [per-channel int samples]) | None   AIFF/AIFF-C PCM (non-WAV)
  reverse_wav(data) -> bytes | None          each channel's samples reversed (backmasking)
  stereo_difference(data) -> bytes | None     a mono WAV of L-R (clamped); None unless >=2 channels
  half_speed(data) -> bytes | None            each sample duplicated (plays at half speed)
  pcm_lsb(samples, msb_first=True) -> bytes   the LSBs of a sample list as bytes (non-WAV LSB)
  analyze(data) -> dict                       {transforms: {name: wav_bytes}, candidates:
                                              [(name, value)], notes: [...]}; all candidates unsure

No `solve_set`, no `signals`: a hand tool, like stego_tools.py.
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
for _p in (str(COMMON), str(HERE)):
    if _p not in sys.path:
        sys.path.append(_p)

import carve_stego as cs       # noqa: E402

MAX_SAMPLES = 8 * 1024 * 1024      # frames read from one recording (bounded)


# ---- WAV read / write ------------------------------------------------------------------------------

def _unsigned_to_signed_list(raw: bytes, width: int, ch: int):
    frames = min(len(raw) // (width * ch), MAX_SAMPLES)
    chans = [[] for _ in range(ch)]
    if width == 1:                      # 8-bit PCM is UNSIGNED
        for f in range(frames):
            base = f * ch
            for c in range(ch):
                chans[c].append(raw[base + c])
    elif width == 2:
        vals = struct.unpack_from(f"<{frames * ch}h", raw, 0)
        for f in range(frames):
            base = f * ch
            for c in range(ch):
                chans[c].append(vals[base + c])
    elif width == 4:
        vals = struct.unpack_from(f"<{frames * ch}i", raw, 0)
        for f in range(frames):
            base = f * ch
            for c in range(ch):
                chans[c].append(vals[base + c])
    else:                               # 24-bit
        for f in range(frames):
            for c in range(ch):
                off = (f * ch + c) * 3
                chans[c].append(int.from_bytes(raw[off:off + 3], "little", signed=True))
    return chans


def wav_channels(data: bytes):
    """(info, [per-channel int samples]) of a PCM WAV, or None. 8-bit is unsigned (0..255), the rest
    signed, so build_wav round-trips the exact bytes."""
    info = cs.wav_info(data)
    if not info or info["data_offset"] is None or info["format"] not in (1, 0xFFFE) or info["bits"] not in (8, 16, 24, 32):
        return None
    width, ch = info["bits"] // 8, info["channels"] or 1
    raw = data[info["data_offset"]:info["data_offset"] + info["data_size"]]
    if ch < 1 or width < 1:
        return None
    return info, _unsigned_to_signed_list(raw, width, ch)


def build_wav(rate: int, bits: int, chans) -> bytes:
    """A canonical PCM WAV from per-channel int samples (lists of equal length)."""
    ch = len(chans)
    width = bits // 8
    frames = min(len(chans[0]) if chans else 0, *(len(c) for c in chans)) if chans else 0
    body = bytearray()
    if width == 1:
        for f in range(frames):
            for c in range(ch):
                body.append(chans[c][f] & 0xFF)
    elif width == 2:
        flat = [chans[c][f] for f in range(frames) for c in range(ch)]
        body += struct.pack(f"<{len(flat)}h", *(_clamp(v, 16) for v in flat))
    elif width == 4:
        flat = [chans[c][f] for f in range(frames) for c in range(ch)]
        body += struct.pack(f"<{len(flat)}i", *(_clamp(v, 32) for v in flat))
    else:
        for f in range(frames):
            for c in range(ch):
                body += _clamp(chans[c][f], 24).to_bytes(3, "little", signed=True)
    byte_rate = rate * ch * width
    block_align = ch * width
    fmt = struct.pack("<HHIIHH", 1, ch, rate, byte_rate, block_align, bits)
    out = bytearray()
    out += b"RIFF" + struct.pack("<I", 4 + (8 + len(fmt)) + (8 + len(body))) + b"WAVE"
    out += b"fmt " + struct.pack("<I", len(fmt)) + fmt
    out += b"data" + struct.pack("<I", len(body)) + bytes(body)
    return bytes(out)


def _clamp(v: int, bits: int) -> int:
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    return lo if v < lo else hi if v > hi else v


# ---- AIFF (non-WAV PCM) ----------------------------------------------------------------------------

def aiff_samples(data: bytes):
    """(rate, bits, [per-channel int samples]) of an AIFF / AIFF-C PCM recording (big-endian), or
    None. Covers the 'non-WAV LSB' case for a sample-LSB read without a sandbox."""
    if data[:4] != b"FORM" or data[8:12] not in (b"AIFF", b"AIFC"):
        return None
    comm = ssnd = None
    i, n = 12, len(data)
    while i + 8 <= n:
        cid = data[i:i + 4]
        size = struct.unpack_from(">I", data, i + 4)[0]
        body = data[i + 8:i + 8 + size]
        if cid == b"COMM":
            comm = body
        elif cid == b"SSND":
            ssnd = body
        i += 8 + size + (size & 1)
    if not comm or ssnd is None or len(comm) < 18:
        return None
    ch, frames, bits = struct.unpack_from(">HIH", comm, 0)
    rate = int(_extended80(comm[8:18]))
    if ch < 1 or bits not in (8, 16, 24, 32):
        return None
    width = bits // 8
    offset, _blocksize = struct.unpack_from(">II", ssnd, 0)
    raw = ssnd[8 + offset:]
    frames = min(frames, len(raw) // (width * ch), MAX_SAMPLES)
    chans = [[] for _ in range(ch)]
    for f in range(frames):
        for c in range(ch):
            off = (f * ch + c) * width
            chans[c].append(int.from_bytes(raw[off:off + width], "big", signed=(width > 1)))
    return rate, bits, chans


def _extended80(b: bytes) -> float:
    """An 80-bit IEEE-754 extended (AIFF sample rate) as a float."""
    if len(b) < 10:
        return 0.0
    sign = -1 if b[0] & 0x80 else 1
    exp = ((b[0] & 0x7F) << 8) | b[1]
    mant = int.from_bytes(b[2:10], "big")
    if exp == 0 and mant == 0:
        return 0.0
    return sign * mant * 2.0 ** (exp - 16383 - 63)


# ---- the transforms --------------------------------------------------------------------------------

def reverse_wav(data: bytes):
    """Each channel's samples reversed (backmasking). Deterministic and self-checking: reversing the
    result round-trips to the original."""
    got = wav_channels(data)
    if not got:
        return None
    info, chans = got
    return build_wav(info["rate"] or 8000, info["bits"], [list(reversed(c)) for c in chans])


def stereo_difference(data: bytes):
    """A mono WAV of channel 0 minus channel 1 (clamped). None unless the recording is >= 2 ch."""
    got = wav_channels(data)
    if not got:
        return None
    info, chans = got
    if len(chans) < 2:
        return None
    bits = info["bits"]
    if bits == 8:                       # unsigned: difference around the 128 midpoint
        diff = [_clamp((a - b) + 128, 8) & 0xFF for a, b in zip(chans[0], chans[1])]
    else:
        diff = [_clamp(a - b, bits) for a, b in zip(chans[0], chans[1])]
    return build_wav(info["rate"] or 8000, bits, [diff])


def half_speed(data: bytes):
    """Each sample duplicated, so the recording plays at half speed (pitch down an octave)."""
    got = wav_channels(data)
    if not got:
        return None
    info, chans = got
    slowed = [[v for s in c for v in (s, s)] for c in chans]
    return build_wav(info["rate"] or 8000, info["bits"], slowed)


def pcm_lsb(samples, msb_first: bool = True) -> bytes:
    """The least significant bits of a sample list as bytes (non-WAV sample-LSB). The bits are packed
    MSB-first by default, like carve_stego's spatial LSB reader."""
    bits = bytearray(s & 1 for s in samples)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        chunk = bits[i:i + 8]
        byte = 0
        for k, b in enumerate(chunk):
            byte |= b << ((7 - k) if msb_first else k)
        out.append(byte)
    return bytes(out)


# ---- the candidate pass ----------------------------------------------------------------------------

def _dtmf(wav_bytes):
    try:
        return cs.dtmf(wav_bytes) or ""
    except Exception:
        return ""


def analyze(data: bytes) -> dict:
    """Ticket C8. Build the transformed recordings and read what is deterministically readable off
    the clock (DTMF via carve_stego). Returns:

      {transforms: {name: wav_bytes}, candidates: [(name, value)], notes: [...]}

    Every candidate is UNSURE (the transform is the author's choice): hand the WAV bytes in
    `transforms` to the sandbox spectrogram / SSTV reader, and the DTMF candidates to the judge only
    as labels.candidates. Never returns a plain answer."""
    out = {"transforms": {}, "candidates": [], "notes": []}
    got = wav_channels(data)
    aiff = None
    if not got:
        aiff = aiff_samples(data)
        if not aiff:
            out["notes"].append("not a PCM WAV or AIFF this reader decodes")
            return out
    if got:
        info, chans = got
        out["notes"].append(f"PCM WAV: {len(chans)} ch, {info['rate']} Hz, {info['bits']} bit")
        for name, fn in (("reversed", reverse_wav), ("stereo_difference", stereo_difference),
                         ("half_speed", half_speed)):
            wav = fn(data)
            if wav is not None:
                out["transforms"][name] = wav
                digits = _dtmf(wav)
                if digits:
                    out["candidates"].append((f"dtmf_{name}", digits))
        # the plain forward reading, for comparison (a baseline, still only a candidate here)
        fwd = _dtmf(data)
        if fwd:
            out["candidates"].append(("dtmf_forward", fwd))
        # non-WAV-style sample LSB over the first channel, as a candidate blob for the agent
        lsb = pcm_lsb(chans[0])
        if lsb.strip(b"\x00"):
            text = cs.as_text(lsb[:256]) if hasattr(cs, "as_text") else None
            if text and text.isprintable():
                out["candidates"].append(("sample_lsb_ch0_text", text.strip()))
    else:
        rate, bits, chans = aiff
        out["notes"].append(f"AIFF PCM (non-WAV): {len(chans)} ch, {rate} Hz, {bits} bit")
        wav = build_wav(rate or 8000, bits, chans)
        out["transforms"]["aiff_as_wav"] = wav
        out["transforms"]["aiff_reversed"] = build_wav(rate or 8000, bits, [list(reversed(c)) for c in chans])
        for name in ("aiff_as_wav", "aiff_reversed"):
            digits = _dtmf(out["transforms"][name])
            if digits:
                out["candidates"].append((f"dtmf_{name}", digits))
        lsb = pcm_lsb(chans[0])
        if lsb.strip(b"\x00"):
            text = cs.as_text(lsb[:256]) if hasattr(cs, "as_text") else None
            if text and text.isprintable():
                out["candidates"].append(("aiff_sample_lsb_ch0_text", text.strip()))
    if not out["candidates"]:
        out["notes"].append("no deterministic reading from any transform (feed the WAV bytes to the "
                            "sandbox spectrogram / SSTV reader)")
    return out


def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    extract = None
    files = []
    it = iter(argv)
    for a in it:
        if a == "--extract":
            extract = Path(next(it, "."))
        elif not a.startswith("--"):
            files.append(a)
    for path in files:
        data = Path(path).read_bytes()
        r = analyze(data)
        print(f"== {path} ({len(data)} bytes)")
        for note in r["notes"]:
            print(f"   note   {note}")
        for name, value in r["candidates"]:
            print(f"   unsure {name}: {value}")
        if extract is not None:
            extract.mkdir(parents=True, exist_ok=True)
            for name, wav in r["transforms"].items():
                dest = extract / f"{Path(path).stem}.{name}.wav"
                dest.write_bytes(wav)
                print(f"   wrote  {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
