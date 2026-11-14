#!/usr/bin/env python3
"""Synthetic regression for solvers/toolkits/audio_tones.py (CyberSonics tone decoder).

Generates tone sequences with KNOWN frequency mappings (numpy), writes them to wav files
(soundfile), and asserts the decoder recovers the planted text / flag. Standalone:

    CTF_WORKDIR=/tmp/ctfws .venv/bin/python tests/test_audio_tones.py   -> prints 'ok', exit 0
"""
import os
import sys
import tempfile
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
sys.path.insert(0, str(ROOT / "solvers" / "common"))

import soundfile as sf                      # noqa: E402
import audio_tones as at                    # noqa: E402

SR = 16000
TONE_MS = 220
GAP_MS = 40
AMP = 0.6


def _tone(freq, ms, sr=SR):
    n = int(sr * ms / 1000.0)
    t = np.arange(n) / sr
    return AMP * np.sin(2 * np.pi * freq * t)


def _silence(ms, sr=SR):
    return np.zeros(int(sr * ms / 1000.0))


def _render(freqs, path, gap_ms=GAP_MS, lead_gap=True):
    """Render a sequence of tones separated by short silence gaps to a wav file."""
    chunks = []
    if lead_gap:
        chunks.append(_silence(gap_ms))
    for f in freqs:
        chunks.append(_tone(f, TONE_MS))
        chunks.append(_silence(gap_ms))
    sig = np.concatenate(chunks).astype(np.float32)
    sf.write(str(path), sig, SR)


def test_linear_explicit(tmp_path):
    """freq = base + step*ord(c); decode with the exact base/step -> recover the flag."""
    flag = "CSCTF{t0ne_l4dd3r_dec0d3d}"
    base, step = 200.0, 20.0
    freqs = [base + step * ord(c) for c in flag]
    wav = tmp_path / "linear.wav"
    _render(freqs, wav)
    res = at.decode(wav, block_ms=None, mode="linear", base=base, step=step)
    text = res["candidates"][0][1]
    assert text == flag, f"linear decode mismatch: {text!r} != {flag!r}"
    assert at.find_flags(res) == [flag], f"flag not highlighted: {at.find_flags(res)}"


def test_autofit(tmp_path):
    """Same ladder, no base/step given -> auto-fit must recover the flag."""
    flag = "CSCTF{aud10_d3cay_r4ce}"
    base, step = 300.0, 25.0
    freqs = [base + step * ord(c) for c in flag]
    wav = tmp_path / "autofit.wav"
    _render(freqs, wav)
    res = at.decode(wav, block_ms=None, mode="auto")
    text = res["candidates"][0][1]
    assert text == flag, f"autofit decode mismatch: {text!r} (base={res['base']} step={res['step']})"
    assert at.find_flags(res) == [flag]


def test_cluster_rank(tmp_path):
    """Fine clustering: only the ORDER of distinct tones matters -> chr(offset + rank).

    Alphabet is contiguous ASCII from the offset and every symbol appears, so cluster rank
    equals (code - offset) and the text comes back exactly.
    """
    offset = 65                               # 'A'
    text = "BADCAFEDAB"                        # chars A..F all present, contiguous from offset
    lo, span = 40.0, 12.0                      # fine 40-100 Hz band
    freqs = [lo + span * (ord(c) - offset) for c in text]
    wav = tmp_path / "cluster.wav"
    _render(freqs, wav)
    res = at.decode(wav, block_ms=None, mode="cluster", offset=offset)
    got = res["candidates"][0][1]
    assert got == text, f"cluster decode mismatch: {got!r} != {text!r} (clusters={res.get('clusters')})"


def test_fixed_block_contiguous(tmp_path):
    """Contiguous tones (no gaps) partitioned by a fixed --block-ms window."""
    flag = "CSCTF{f1x3d_bl0ck}"
    base, step = 250.0, 22.0
    block_ms = TONE_MS
    chunks = [_tone(base + step * ord(c), block_ms) for c in flag]
    sig = np.concatenate(chunks).astype(np.float32)
    wav = tmp_path / "fixed.wav"
    sf.write(str(wav), sig, SR)
    res = at.decode(wav, block_ms=block_ms, mode="linear", base=base, step=step)
    text = res["candidates"][0][1]
    assert text == flag, f"fixed-block decode mismatch: {text!r} != {flag!r}"


def test_dual_stream_xor(tmp_path):
    """CyberSonics-2: two tone streams split by a long silence, XORed byte-for-byte -> flag."""
    flag = b"CSCTF{x0r_tw0_t0nes}"
    key = bytes([(i * 13 + 7) & 0x7F for i in range(len(flag))])   # keep codes < 128
    stream0 = [f ^ k for f, k in zip(flag, key)]                   # flag XOR key
    stream1 = list(key)                                            # key
    base, step = 300.0, 18.0

    def freqs_of(codes):
        return [base + step * c for c in codes]

    chunks = [_silence(GAP_MS)]
    for f in freqs_of(stream0):
        chunks += [_tone(f, TONE_MS), _silence(GAP_MS)]
    chunks.append(_silence(400))                                  # the long inter-stream gap
    for f in freqs_of(stream1):
        chunks += [_tone(f, TONE_MS), _silence(GAP_MS)]
    sig = np.concatenate(chunks).astype(np.float32)
    wav = tmp_path / "xor.wav"
    sf.write(str(wav), sig, SR)

    res = at.decode(wav, block_ms=None, mode="linear", base=base, step=step, xor=True)
    assert res["n_streams"] == 2, f"expected 2 streams, got {res['n_streams']}"
    cands = dict(res["candidates"])
    recovered = cands.get("xor(codes)", "")
    assert recovered == flag.decode(), f"xor decode mismatch: {recovered!r} != {flag.decode()!r}"
    assert at.find_flags(res) == [flag.decode()], f"flag not highlighted: {at.find_flags(res)}"


def main():
    os.environ.setdefault("CTF_WORKDIR", "/tmp/ctfws")
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        test_linear_explicit(tmp)
        test_autofit(tmp)
        test_cluster_rank(tmp)
        test_fixed_block_contiguous(tmp)
        test_dual_stream_xor(tmp)
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
