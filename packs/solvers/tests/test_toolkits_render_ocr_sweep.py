"""B-126: the render-and-read stego sweep (solvers/toolkits/render_ocr_sweep.py), its checklist CLI
(ctf/cli/render_sweep.py) and the survey row in stego_tools. Every fixture is built here: synthetic
samples, pixels drawn with numpy and Pillow's own font, our own WAV and PNG encoding. Nothing from a
challenge is read, and no text here is a past challenge's: the flags, the drawn lines, the notes and
the plaintexts are all made up for these tests (only the shapes are those of the Spooky 2026 rows).
Budgets are given explicitly and are far above what the work takes (the machine is shared); no test
asserts an upper bound on elapsed time."""
from __future__ import annotations

import argparse
import base64
import codecs
import datetime as dt
import functools
import io
import json
import re
import struct
import sys
import threading
import time
import types
import wave
from pathlib import Path

import numpy as np
import pytest

import image_carve as ic
import render_ocr_sweep as ros
import signal_stego_depth as sd
import steganalysis as sa
from ctf import event, flagfmt
from ctf import hypothesis as hyp

REPO = Path(__file__).resolve().parents[1]
RATE = 44100
LONG = 3600.0                      # an explicit budget no test comes near


def _profile(prefixes=("CSCTF",), slug="b126-test"):
    return event.parse({
        "slug": slug, "name": "render sweep test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "manual"},
        "flag": {"prefixes": list(prefixes)},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
    }, src="<test>")


PROFILE = _profile()
FF = flagfmt.for_profile(PROFILE)
SPOOKY = _profile(("spooky",), "b126-spooky")
SFF = flagfmt.for_profile(SPOOKY)
PORTRAIT_FLAG = "spooky{painted_plane_fixture}"            # made up for this file
PORTRAIT_CIPHER = "fcbbxl{cnvagrq_cynar_svkgher}"          # its ROT13
PORTRAIT_MISREAD = "febbxlicnvagrq_cynar_svkgher}"         # what tesseract 5 made of that line: c as e, { as i
PORTRAIT_LINES = ("A SYNTHETIC CANVAS:", "THE LAST LINE IS ROT13", PORTRAIT_CIPHER)
SIBLING_NOTE = b"a made-up note (2) (18 lanterns, all synthetic)"
LEAD = "PUMPKINLANTERN"                                    # a plaintext with no flag shape


# ---- fixture builders ------------------------------------------------------------------------------

def _wav(samples, rate=RATE) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes((np.clip(samples, -1, 1) * 32767).astype("<i2").tobytes())
    return buf.getvalue()


def _glyph_samples(text, base, step, col_ms, lead=0.4, tail=0.3, top_row_highest=False, flip=None, seed=5):
    """Our own 5x7 writer: each glyph column is `col_ms` of the tones of its set rows, then one silent
    column. flip=(glyph, row, col) inverts one cell, so the glyph is no longer in the font."""
    rng = np.random.default_rng(seed)
    width = int(round(RATE * col_ms / 1000))
    n = np.arange(width)
    chunks = [np.zeros(int(lead * RATE))]
    for gi, ch in enumerate(text):
        pat = [list(row) for row in sd.FONT_5X7[ch]]
        if flip is not None and flip[0] == gi:
            pat[flip[1]][flip[2]] = "0" if pat[flip[1]][flip[2]] == "1" else "1"
        for c in range(5):
            seg = np.zeros(width)
            for r in range(7):
                if pat[r][c] == "1":
                    seg += 0.11 * np.sin(2 * np.pi * (base + ((6 - r) if top_row_highest else r) * step) * n / RATE)
            chunks.append(seg)
        chunks.append(np.zeros(width))
    chunks.append(np.zeros(int(tail * RATE)))
    a = np.concatenate(chunks)
    return a + rng.normal(0, 0.0005, a.size)


def _text_bits(lines, size=30, w=840, h=655) -> np.ndarray:
    """Lines of text as a 0/1 picture, drawn with Pillow's built-in scalable font."""
    from PIL import Image, ImageDraw, ImageFont
    im = Image.new("L", (w, h), 0)
    d = ImageDraw.Draw(im)
    font = ImageFont.load_default(size=size)
    y = 40
    for line in lines:
        d.text((40, y), line, fill=255, font=font)
        y += int(size * 2.2)
    return (np.asarray(im) > 127).astype(np.uint8)


def _png(arr: np.ndarray) -> bytes:
    from PIL import Image
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, "PNG")
    return buf.getvalue()


def _cover(h, w, channels=3, seed=7) -> np.ndarray:
    return np.random.default_rng(seed).integers(0, 256, (h, w, channels), dtype=np.uint8)


def _with_plane(arr, channel, bit, bits) -> np.ndarray:
    out = arr.copy()
    out[:, :, channel] = (out[:, :, channel] & ~np.uint8(1 << bit)) | (bits.astype(np.uint8) << bit)
    return out


def _strokes(h=128, w=160) -> np.ndarray:
    """A sparse drawing (a few thin strokes on black): under 3% ink, like a line of letters."""
    bits = np.zeros((h, w), dtype=np.uint8)
    for y in (30, 80):
        bits[y:y + 2, 20:120] = 1
    for x in (40, 90):
        bits[20:100, x] = 1
    return bits


@functools.lru_cache(maxsize=None)
def _portrait() -> bytes:
    """A noise cover whose blue bit 0 holds three drawn lines, the last a flag under ROT13."""
    return _png(_with_plane(_cover(655, 840), 2, 0, _text_bits(PORTRAIT_LINES)))


@functools.lru_cache(maxsize=None)
def _whisper(text="GHOST HOUSE 4242", lo=8400.0, hi=10600.0, per_char=0.2) -> bytes:
    """A recording with `text` drawn in its spectrogram between lo and hi Hz, over a steady 440 Hz
    tone, a tone at 1320 Hz that comes and goes, and a little noise; a second of nothing each side."""
    from PIL import Image, ImageDraw, ImageFont
    font = ImageFont.load_default(size=40)
    box = font.getbbox(text)
    im = Image.new("L", (box[2] + 8, box[3] + 8), 0)
    ImageDraw.Draw(im).text((4, 4), text, fill=255, font=font)
    bitmap = np.asarray(im) > 127
    rng = np.random.default_rng(1)
    h, w = bitmap.shape
    n = int(per_char * len(text) * RATE)
    t = np.arange(n) / RATE
    col = np.minimum((np.arange(n) * w) // n, w - 1)
    fade = np.hanning(265) / np.hanning(265).sum()
    out = np.zeros(n)
    for r in range(h):
        if bitmap[r].any():
            f = hi - (hi - lo) * r / (h - 1)
            out += np.convolve(bitmap[r, col].astype(float), fade, "same") * np.sin(2 * np.pi * f * t + rng.uniform(0, 6.28))
    out *= 0.5 / np.abs(out).max()
    pad = np.zeros(RATE)
    sig = np.concatenate([pad, out, pad])
    tt = np.arange(sig.size) / RATE
    music = 0.3 * np.sin(2 * np.pi * 440 * tt) + 0.2 * np.sin(2 * np.pi * 1320 * tt) * (np.sin(2 * np.pi * 2 * tt) > 0)
    return _wav(sig + music + rng.normal(0, 0.002, sig.size))


def _lsb_note(note: bytes, h=64, w=96, seed=9) -> bytes:
    """A PNG whose RGB bit 0, row by row, MSB first, holds a 4-byte big-endian length and a text."""
    arr = _cover(h, w, seed=seed)
    bits = np.unpackbits(np.frombuffer(struct.pack(">I", len(note)) + note, dtype=np.uint8))
    flat = arr.reshape(-1)
    flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits
    return _png(arr)


class StubOCR:
    """An OCR stand-in for the tests of the sweep's own logic: it records each call and answers with
    `answer(png, scale)`. The readers under test (rendering, scoring, ordering, decoding) are real."""

    def __init__(self, answer=lambda png, scale: ""):
        self.answer, self.calls = answer, []

    def __call__(self, png, scale=1, deadline=None):
        self.calls.append((png, scale))
        return self.answer(png, scale)


def _no_tesseract(monkeypatch):
    monkeypatch.setattr(ic.shutil, "which", lambda name: None)


# ---- the band plan ---------------------------------------------------------------------------------

def test_bands_reach_nyquist_in_overlapping_bands():
    plan = ros.bands(22050.0)
    assert plan[0] == (0.0, 22050.0, ros.WHOLE_NFFT)
    for width, nfft in ros.BAND_PLAN:
        mine = [(lo, hi) for lo, hi, n in plan if n == nfft]
        assert mine[0][0] == 0.0 and mine[-1][1] == 22050.0          # from 0 Hz to Nyquist, nothing cut
        assert all(hi - lo == width for lo, hi in mine)
        for (lo_a, hi_a), (lo_b, _hi_b) in zip(mine, mine[1:]):
            assert lo_a < lo_b <= lo_a + width * 0.625 and lo_b < hi_a   # each band starts inside the one before
    # the writing the carried reader missed sat at 8.2 to 10.6 kHz: one 4 kHz band holds all of it
    assert any(lo <= 8200 and hi >= 10600 for lo, hi, n in plan if n == 1024)


def test_bands_top_hz_and_narrow_recordings():
    capped = ros.bands(22050.0, top_hz=8000)
    assert max(hi for _lo, hi, _n in capped) == 8000.0 and capped[0] == (0.0, 8000.0, ros.WHOLE_NFFT)
    assert ros.bands(22050.0, top_hz=99999)[0][1] == 22050.0         # never past Nyquist
    assert ros.bands(4000.0) == [(0.0, 4000.0, ros.WHOLE_NFFT)]      # an 8 kHz recording: one picture


def test_windows_cover_a_long_recording_with_overlap():
    assert ros.windows(20 * RATE, RATE) == [(0, 20 * RATE)]
    assert ros.windows(25 * RATE, RATE) == [(0, 25 * RATE)]
    n = 65 * RATE + 123
    ws = ros.windows(n, RATE)
    assert ws[0][0] == 0 and ws[-1][1] == n
    assert all(b - a == 20 * RATE for a, b in ws)
    assert all(nxt[0] - cur[0] <= 11.25 * RATE and nxt[0] < cur[1] for cur, nxt in zip(ws, ws[1:]))
    exact = ros.windows(60 * RATE + 5, RATE)                                # 5 samples over: no window of its own
    assert len(exact) == 5 and exact[-1] == (40 * RATE + 5, 60 * RATE + 5)


# ---- ink: what counts as drawn ---------------------------------------------------------------------

def test_noise_and_a_steady_tone_render_blank():
    rng = np.random.default_rng(3)
    t = np.arange(6 * RATE) / RATE
    audio = sd.Audio(RATE, rng.normal(0, 0.05, t.size) + 0.4 * np.sin(2 * np.pi * 3000 * t))
    rs = ros.renderings(audio)
    assert len(rs) == len(ros.bands(RATE / 2)) and all(r.blank and r.png is None for r in rs)
    assert max(r.ink for r in rs) < ros.BLANK / 2


def test_a_burst_is_ink_and_the_two_polarities_are_inverses():
    from PIL import Image
    rng = np.random.default_rng(4)
    t = np.arange(6 * RATE) / RATE
    fade = np.clip((t - 2.0) / 0.05, 0, 1) * np.clip((3.0 - t) / 0.05, 0, 1)      # no click at its ends
    burst = 0.3 * np.sin(2 * np.pi * 9500 * t) * fade
    rs = ros.renderings(sd.Audio(RATE, rng.normal(0, 0.002, t.size) + burst))
    drawn = [r for r in rs if not r.blank]
    assert drawn and all(r.lo <= 9500 <= r.hi for r in drawn)          # only bands that hold 9.5 kHz
    assert all(r.blank for r in rs if r.lo > 9600 or r.hi < 9400)
    by_span = {}
    for r in drawn:
        by_span.setdefault(r.where.rsplit(", ", 1)[0], {})["light" if r.light else "dark"] = r
    assert all(set(v) == {"light", "dark"} for v in by_span.values())
    pair = next(iter(by_span.values()))
    light = np.asarray(Image.open(io.BytesIO(pair["light"].png)), dtype=int)
    dark = np.asarray(Image.open(io.BytesIO(pair["dark"].png)), dtype=int)
    assert light.shape == dark.shape and np.abs(light + dark - 255).max() <= 1
    assert light[0, 0] == 255 and dark[0, 0] == 0                      # the margin is background
    assert light.min() == 0                                           # and the burst is full ink
    # high frequencies are at the top: 9.5 kHz sits five eighths of the way down a picture of 8 to 12 kHz
    band = next(v for k, v in by_span.items() if k.startswith("8000-12000 Hz"))["light"]
    px = np.asarray(Image.open(io.BytesIO(band.png)), dtype=int)[ros.MARGIN:-ros.MARGIN, ros.MARGIN:-ros.MARGIN]
    rows = np.flatnonzero((px == 0).any(axis=1))
    assert 0.55 < rows.mean() / px.shape[0] < 0.70


@pytest.mark.needs_tool("py:PIL")
def test_writing_at_8_to_11_khz_is_ink_only_where_it_is():
    audio = sd.read_audio(_whisper())
    rs = ros.renderings(audio)
    assert any(not r.blank and (r.lo, r.hi) == (8000.0, 12000.0) for r in rs)
    assert all(r.blank for r in rs if r.lo >= 12000)                   # nothing drawn above the writing
    capped = ros.renderings(audio, top_hz=8000)
    assert capped and max(r.hi for r in capped) == 8000.0              # the old cap never looks at it


def test_a_long_recording_is_read_in_overlapping_windows_and_a_short_mark_still_counts():
    rng = np.random.default_rng(6)
    n = 45 * RATE
    t = np.arange(n) / RATE
    fade = np.clip((t - 31.0) / 0.05, 0, 1) * np.clip((32.0 - t) / 0.05, 0, 1)
    rs = ros.renderings(sd.Audio(RATE, rng.normal(0, 0.002, n) + 0.3 * np.sin(2 * np.pi * 9500 * t) * fade))
    assert sorted({r.where.split(", ")[1] for r in rs}) == ["0.0-20.0 s", "10.0-30.0 s", "20.0-40.0 s", "25.0-45.0 s"]
    # one second of one tone is a few rows of a 20 s picture: under 0.4% of it, and still not blank
    drawn = [r for r in rs if not r.blank]
    assert {r.where.split(", ")[1] for r in drawn} == {"20.0-40.0 s", "25.0-45.0 s"}
    assert all(r.lo <= 9500 <= r.hi for r in drawn) and min(r.ink for r in drawn) < 0.004


# ---- full-band OCR (tesseract) ---------------------------------------------------------------------

@pytest.mark.needs_tool("tesseract", "py:PIL")
def test_full_band_ocr_reads_writing_the_8_khz_cap_missed():
    """The phasmophobia shape: writing drawn at 8.4 to 10.6 kHz. Read to Nyquist it is read; read
    only to 8 kHz (what stego_tools.spectrogram_text does by default) it is not."""
    files = {"files/whisper.wav": _whisper()}
    rep = ros.examine(files, FF, prefixes=("CSCTF",), deadline=time.monotonic() + LONG, ledger=False)
    hits = [r for r in rep.readings if r.probe == ros.PROBE_SPEC and "GHOST HOUSE" in r.text]
    assert {r.where for r in hits} >= {"8000-12000 Hz, 0.0-5.2 s, light", "8000-12000 Hz, 0.0-5.2 s, dark"}
    assert all(float(r.where.split(" Hz")[0].split("-")[1]) > 8000 for r in hits)   # never in a band under the cap
    assert rep.ocr == "run" and "22050 Hz (Nyquist)" in rep.files["files/whisper.wav"]["detail"]
    res = ros.result_of(rep)
    assert res.status == "unsure" and not res.flags and "GHOST HOUSE" in res.notes
    capped = ros.examine(files, FF, prefixes=("CSCTF",), deadline=time.monotonic() + LONG, ledger=False, top_hz=8000)
    assert not any("GHOST" in r.text for r in capped.readings)
    assert any("read only to 8000 Hz" in s and "8000 to 22050 Hz was not looked at" in s for s in capped.skipped)


# ---- exact 5x7 glyphs, measured --------------------------------------------------------------------

@pytest.mark.parametrize("text, base, step, col_ms, lead, highest", [
    ("CSCTF{A1}", 500, 180, 35, 0.0, False),                  # the carried reader's own defaults, from sample 0
    ("SPOOKY{HIGH_BAND_5X7}", 9000, 250, 40, 0.73, False),    # above the old 8 kHz cap, after a silence
    ("1CSCTF{TOP-ROW:HIGHEST}", 12000, 180, 35, 0.31, True),  # the font's top row on the highest tone
    ("FLAG{" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" * 2 + "}", 3000, 300, 30, 1.234, False),
], ids=["defaults-from-zero", "high-band", "top-row-highest", "long-text"])
def test_glyph_text_measures_rows_columns_and_start(text, base, step, col_ms, lead, highest):
    samples = _glyph_samples(text, base, step, col_ms, lead=lead, top_row_highest=highest)
    got = ros.glyph_text(sd.Audio(RATE, samples))
    assert [t for t, _how in got] == [text]
    how = got[0][1]
    assert ("top row highest" if highest else "top row lowest") in how and f"{col_ms:.1f} ms columns" in how
    # the carried reader, left at its own defaults, cannot see writing it was not told the place of
    if (base, step, col_ms, lead) != (500, 180, 35, 0.0):
        assert sd.decode_spectrogram_text(sd.Audio(RATE, samples)) is None


def test_glyph_text_declines_what_is_not_exact_glyphs():
    rng = np.random.default_rng(1)
    assert ros.glyph_text(sd.Audio(RATE, rng.normal(0, 0.1, RATE * 8))) == []
    t = np.arange(RATE * 6) / RATE
    harmonics = sum(np.sin(2 * np.pi * f * t) * (np.sin(2 * np.pi * (0.5 + i) * t) > 0)
                    for i, f in enumerate((220, 440, 660, 880, 1100, 1320, 1540)))
    assert ros.glyph_text(sd.Audio(RATE, 0.1 * harmonics)) == []          # seven tones, but no glyph grid
    good = _glyph_samples("CSCTF{A1}", 9000, 250, 40)
    assert [t for t, _ in ros.glyph_text(sd.Audio(RATE, good))] == ["CSCTF{A1}"]
    bad = _glyph_samples("CSCTF{A1}", 9000, 250, 40, flip=(1, 0, 0))      # one cell of the S inverted
    assert ros.glyph_text(sd.Audio(RATE, bad)) == []
    assert ros.glyph_text(sd.Audio(RATE, np.zeros(100))) == []            # shorter than one window


def test_a_glyph_flag_is_solved_with_no_tesseract(tmp_path, monkeypatch):
    _no_tesseract(monkeypatch)
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "tones.wav").write_bytes(_wav(_glyph_samples("CSCTF{HIGH_BAND_5X7}", 9000, 250, 40)))
    res = ros.solve(tmp_path, PROFILE, seconds=LONG, ledger="off")
    assert res.status == "solved" and res.flags == ("CSCTF{HIGH_BAND_5X7}",) and res.engine == ros.ENGINE
    proof = res.evidence[0]
    assert proof.kind == "decode" and proof.path == "files/tones.wav" and "exact 5x7 glyph read" in proof.detail
    assert "9000 Hz + 250 Hz" in proof.detail
    assert "OCR not run: tesseract is not on PATH" in res.notes          # said, not hidden
    blocked = ros.solve(tmp_path, PROFILE, seconds=LONG, ocr="on", ledger="off")
    assert blocked.status == "blocked" and "tesseract is not on PATH" in blocked.notes and not blocked.flags


def test_a_glyph_flag_under_a_rotation_is_only_a_candidate():
    cipher = ros.caesar("CSCTF{ROTATED_GLYPHS}", 7)
    rep = ros.examine({"a.wav": _wav(_glyph_samples(cipher, 4000, 250, 40))}, FF, prefixes=("CSCTF",), ocr="off",
                      ledger=False)
    res = ros.result_of(rep)
    assert res.status == "candidate" and res.flags == ("CSCTF{ROTATED_GLYPHS}",)
    assert "exact 5x7 glyph read then caesar+19" in res.evidence[0].detail


def test_audio_that_is_not_pcm_wav_is_named_not_skipped_silently():
    riff = b"RIFF" + struct.pack("<I", 36) + b"WAVEfmt " + struct.pack("<IHHIIHH", 16, 85, 1, 44100, 16000, 1, 0) \
        + b"data" + struct.pack("<I", 0)                                 # format tag 85: MPEG layer 3 in a WAV
    rep = ros.examine({"a.wav": riff, "b.flac": b"fLaC" + bytes(64), "c.txt": b"hello"}, FF, ocr="off")
    assert any("a.wav" in s and "not PCM WAV" in s for s in rep.skipped)
    assert any("b.flac: FLAC audio is not read here" in s for s in rep.skipped)
    assert list(rep.files) == ["a.wav"]
    item = next(i for i in ros.checklist(rep) if i["probe"] == ros.PROBE_SPEC)
    assert item["result"] == "error" and "not PCM WAV" in item["evidence"]   # never a negative


# ---- bit planes ------------------------------------------------------------------------------------

def test_plane_structure_tells_a_drawing_from_noise():
    rng = np.random.default_rng(2)
    noise = rng.integers(0, 2, (128, 160), dtype=np.uint8)
    st = ros.plane_structure(noise)
    assert not st["structured"] and st["score"] < 0.05 and st["flat"] == 0.0 and not st["blank"]
    sparse_noise = (rng.random((128, 160)) < 0.03).astype(np.uint8)       # 3% ones, but scattered: not a drawing
    assert ros.plane_structure(sparse_noise)["score"] < 0.05
    drawn = ros.plane_structure(_strokes())
    assert drawn["structured"] and drawn["score"] > 0.5 and 0.01 < drawn["density"] < 0.04
    for constant in (np.zeros((128, 160), dtype=np.uint8), np.ones((128, 160), dtype=np.uint8)):
        st = ros.plane_structure(constant)
        assert st["blank"] and not st["structured"]
    # a drawing written over one corner of a noise plane: the agreement score is diluted, the flat tiles are not
    patch = noise.copy()
    patch[:64, :64] = 0
    patch[20:23, 4:60] = 1
    st = ros.plane_structure(patch)
    assert st["structured"] and st["flat"] >= ros.FLAT_TILES_MIN


def test_the_sparse_plane_steganalysis_rejects_is_still_read():
    """steganalysis.lsb_plane_score damps a biased plane, so a few letters on black (the Spooky
    portrait: about 1% ink) score under its lowest threshold. The sweep's own score does not."""
    arr = _with_plane(_cover(128, 160), 2, 0, _strokes())
    assert sa.lsb_plane_score(arr, channel=2, bit=0, structure_threshold=0.5) is None
    ocr = StubOCR()
    rep = ros.examine({"p.png": _png(arr)}, FF, read=ocr, ledger=False)
    drawn = [r for r in rep.readings if r.png is not None]
    assert [r.where for r in drawn] == ["B bit 0"] and drawn[0].state == ros.READ
    assert re.fullmatch(r"agreement score 0\.[5-9]\d, \d+% flat tiles, density 0\.02\d; "
                        r"steganalysis spatial-bitplane/visual-structure: under its threshold", drawn[0].note)
    # a plane half ones, half zeros is structure both tests see: steganalysis's verdict is on record
    halves = np.zeros((128, 160), dtype=np.uint8)
    halves[:, 80:] = 1
    both = ros.examine({"h.png": _png(_with_plane(_cover(128, 160), 0, 0, halves))}, FF, read=StubOCR(), ledger=False)
    note = next(r for r in both.readings if r.png is not None).note
    assert re.search(r"; steganalysis spatial-bitplane/visual-structure 0\.9\d$", note)
    assert all(r.note == "" for r in both.readings if r.png is None)
    assert "1 of 9 planes structured (R bit 0)" in ros.result_of(both).notes
    assert len(rep.readings) == 9 and {r.where for r in rep.readings} == {f"{c} bit {b}" for c in "RGB" for b in (0, 1, 2)}
    assert all(r.state == ros.BLANK_STATE and r.why == "no spatial structure (noise)" for r in rep.readings if r.png is None)
    assert [scale for _png_, scale in ocr.calls] == [1, 2, 3]            # a small plane is read at three sizes
    from PIL import Image
    px = np.asarray(Image.open(io.BytesIO(drawn[0].png)))
    inner = px[ros.MARGIN:-ros.MARGIN, ros.MARGIN:-ros.MARGIN]
    assert np.array_equal(inner == 0, _strokes() == 1)                   # the rarer value is the dark ink
    assert px[0, 0] == 255


def test_a_dense_plane_is_rendered_with_its_rarer_value_dark():
    from PIL import Image
    inverse = 1 - _strokes()                                             # a few holes in a plane of ones
    px = np.asarray(Image.open(io.BytesIO(ros.render_plane(inverse))))
    inner = px[ros.MARGIN:-ros.MARGIN, ros.MARGIN:-ros.MARGIN]
    assert np.array_equal(inner == 0, inverse == 0) and (inner == 0).mean() < 0.1


def test_alpha_and_bits_one_and_two_are_swept_too():
    arr = _with_plane(_with_plane(_cover(128, 160, 4), 3, 2, _strokes()), 1, 1, _strokes())
    rep = ros.examine({"p.png": _png(arr)}, FF, read=StubOCR(), ledger=False)
    assert len(rep.readings) == 12
    assert sorted(r.where for r in rep.readings if r.png is not None) == ["A bit 2", "G bit 1"]
    assert "RGBA" in rep.files["p.png"]["detail"]


def test_bmp_tiff_and_ppm_are_swept_and_wide_samples_are_refused_by_name(monkeypatch):
    from PIL import Image
    arr = _with_plane(_cover(128, 160), 0, 0, _strokes())
    files = {}
    for fmt in ("BMP", "TIFF", "PPM"):
        buf = io.BytesIO()
        Image.fromarray(arr).save(buf, fmt)
        files[f"p.{fmt.lower()}"] = buf.getvalue()
    for name, data in files.items():
        rep = ros.examine({name: data}, FF, read=StubOCR(), ledger=False)
        assert [r.where for r in rep.readings if r.png is not None] == ["R bit 0"], name
    buf = io.BytesIO()
    Image.fromarray(np.arange(64 * 64, dtype=np.uint16).reshape(64, 64)).save(buf, "PNG")
    rep = ros.examine({"deep.png": buf.getvalue()}, FF, read=StubOCR(), ledger=False)
    assert [(r.state, r.png) for r in rep.readings] == [(ros.NOT_READ, None)]
    assert rep.skipped == ["deep.png: bit planes not read: PNG mode I;16: samples wider than 8 bits, whose low planes "
                           "are not read here"]
    assert ros.checklist(rep)[0]["result"] == "error"                    # never 'ruled out'
    monkeypatch.setattr(ros, "MAX_PIXELS", 100)
    with pytest.raises(ValueError, match="160x128 is over 100 pixels"):
        ros.image_array(files["p.bmp"])


def test_plane_ocr_scales_shrink_with_the_picture():
    assert ros.plane_ocr_scales(655, 840) == (1, 2, 3)
    assert ros.plane_ocr_scales(999, 10) == (1, 2, 3) and ros.plane_ocr_scales(1000, 10) == (1, 2)
    assert ros.plane_ocr_scales(3044, 2499) == (1,) and ros.plane_ocr_scales(10, 2499) == (1, 2)


def test_a_jpeg_is_not_given_planes_and_a_picture_that_does_not_open_is_named():
    from PIL import Image
    buf = io.BytesIO()
    Image.fromarray(_cover(64, 64)).save(buf, "JPEG")
    assert ros.image_array(buf.getvalue()) is None                       # recompressed samples are not stored bits
    bmp = io.BytesIO()
    Image.fromarray(_cover(16, 16)).save(bmp, "BMP")
    broken_bmp = bmp.getvalue()[:14] + b"\xff" * 4 + bmp.getvalue()[18:]     # the header size field overwritten
    files = {"a.jpg": buf.getvalue(), "b.png": ic.PNG_SIG + b"not a picture at all", "c.bmp": broken_bmp,
             "d.tif": b"II*\x00" + bytes(40), "e.ppm": b"P6\n\xff\xfe\x00 broken", "notes.txt": b"BM stands for bitmap, "
             b"but this file is only words about one.", "list.txt": b"P5 and P6 are the binary PGM and PPM kinds."}
    rep = ros.examine(files, FF, read=StubOCR(), ledger=False)
    # the JPEG and the two text files are not pictures here; the four damaged ones stay in the report, named
    assert sorted(rep.files) == ["b.png", "c.bmp", "d.tif", "e.ppm"]
    assert [(r.file, r.probe, r.state, r.png) for r in rep.readings] == [
        (n, ros.PROBE_PLANE, ros.NOT_READ, None) for n in ("b.png", "c.bmp", "d.tif", "e.ppm")]
    for name, fmt in (("b.png", "PNG"), ("c.bmp", "BMP"), ("d.tif", "TIFF"), ("e.ppm", "PPM")):
        note = next(x for x in rep.skipped if x.startswith(f"{name}: "))
        assert f"bit planes not read: {fmt} magic, but the picture does not open" in note and "repair its header" in note
    items = ros.checklist(rep)
    assert [(i["file"], i["result"]) for i in items[:4]] == [(n, "error") for n in ("b.png", "c.bmp", "d.tif", "e.ppm")]
    assert "[not run   ] bitplane-ocr     b.png" in ros.checklist_text(items)
    assert [i["result"] for i in items[4:]] == ["error", "error"]        # nothing was read: nothing is ruled out
    with pytest.raises(ValueError, match="PNG magic, but the picture does not open"):
        ros.image_array(files["b.png"])
    assert ros.claimed_format(files["notes.txt"]) is None and ros.claimed_format(files["a.jpg"]) is None


@pytest.mark.needs_tool("tesseract", "py:PIL")
def test_text_in_a_bit_plane_under_rot13_closes_with_no_model(tmp_path):
    """The haunted-portrait shape: three lines drawn in blue bit 0, the last the flag under ROT13."""
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "portrait.png").write_bytes(_portrait())
    res = ros.solve(tmp_path, SPOOKY, seconds=LONG, ledger="off")
    assert res.status == "candidate" and res.flags[0] == PORTRAIT_FLAG     # OCR is never more than a candidate
    proof = res.evidence[0]
    assert proof.kind == "ocr" and proof.path == "files/portrait.png"
    assert "bitplane-ocr: B bit 0" in proof.detail and "rot13" in proof.detail
    assert "1 of 9 planes structured (B bit 0)" in res.notes and "THE LAST LINE IS ROT13" in res.notes
    out = tmp_path / "recon" / "render_ocr_sweep"
    assert [p.name for p in sorted(out.glob("*.png"))] == ["files_portrait.png.bitplane-ocr.B_bit_0.png"]
    assert (out / "report.json").is_file()


# ---- text to flags ---------------------------------------------------------------------------------

def test_text_flags_reads_the_flag_as_it_stands_and_under_keyless_layers():
    assert ros.text_flags("noise\nCSCTF{plain_read}\nmore", FF, ("CSCTF",)) == [("CSCTF{plain_read}", ())]
    assert ros.text_flags("CSCTF(brace_slip)", FF, ("CSCTF",)) == [("CSCTF{brace_slip}", ())]
    assert codecs.encode(PORTRAIT_FLAG, "rot13") == PORTRAIT_CIPHER       # the fixture is what it says it is
    got = dict(ros.text_flags(f"THE LAST LINE IS ROT13\n{PORTRAIT_CIPHER}", SFF, ("spooky",)))
    assert got == {PORTRAIT_FLAG: ("rot13",)}
    slipped = dict(ros.text_flags(f"THE LAST LINE IS ROT13\n{PORTRAIT_MISREAD}", SFF, ("spooky",)))
    assert slipped == {PORTRAIT_FLAG: ("rot13", ros.MENDED)}              # what OCR really made of that line
    wrapped = base64.b64encode(b"CSCTF{under_base64}").decode()
    got = dict(ros.text_flags(f"a line\n{wrapped}\n", FF, ("CSCTF",)))
    assert list(got) == ["CSCTF{under_base64}"] and got["CSCTF{under_base64}"]      # crib_decode's chain, not ()
    assert ros.text_flags("hello world {nothing} here\nfoo{bar}", FF, ("CSCTF",)) == []
    # crib_decode also reads the text case-flipped (xor 0x20 turns _ into DEL) and upper-cased: neither is a second flag
    loose = flagfmt.for_profile(event.load("spooky"))                      # prefix in any case
    assert ros.text_flags("SPOOKY{Mixed_Case}", loose, ("spooky",)) == [("SPOOKY{Mixed_Case}", ())]
    assert ros.text_flags("SPOOKY{NoUnderscoreHere}", loose, ("spooky",)) == [("SPOOKY{NoUnderscoreHere}", ())]


def test_rotated_flags_mends_what_ocr_does_to_ciphertext():
    # what tesseract really made of the fixture's last line (PORTRAIT_MISREAD): c read as e, the brace as i
    got = ros.rotated_flags(PORTRAIT_MISREAD, SFF, ("spooky",))
    assert got == {PORTRAIT_FLAG: ("rot13", ros.MENDED)}
    assert ros.rotated_flags(PORTRAIT_CIPHER, SFF, ("spooky",)) == {PORTRAIT_FLAG: ("rot13",)}
    assert ros.rotated_flags(ros.caesar("spooky{five_back}", -5), SFF, ("spooky",)) == {"spooky{five_back}": ("caesar+5",)}
    assert ros.rotated_flags("spo0ky(mended_plain)", SFF, ("spooky",)) == {"spooky{mended_plain}": (ros.MENDED,)}
    assert ros.rotated_flags("fxbbxyicnvagrq}", SFF, ("spooky",)) == {}               # two characters off: not mended
    assert ros.rotated_flags("xspooky{glued}", SFF, ("spooky",)) == {}                # not on a word start
    assert ros.rotated_flags("spooky label)", SFF, ("spooky",)) == {}                 # a letter is a brace only when glued on
    assert ros.rotated_flags("spooky (spaced_bracket)", SFF, ("spooky",)) == {"spooky{spaced_bracket}": ()}
    short = flagfmt.for_profile(_profile(("ctf",), "b126-short"))
    assert ros.rotated_flags("cxf{too_short_to_mend}", short, ("ctf",)) == {}         # a 3-letter prefix is never mended
    assert ros.rotated_flags("ctf{kept}", short, ("ctf",)) == {"ctf{kept}": ()}


def test_an_unknown_flag_prefix_gets_no_rotation_search():
    unknown = flagfmt.for_profile(_profile((), "b126-unknown"))
    assert not unknown.known
    skipped = []
    got = ros.text_flags(PORTRAIT_CIPHER, unknown, (), skipped=skipped)
    assert got == [(PORTRAIT_CIPHER, ())]                                  # as it stands only: any word{...} fits
    assert skipped == ["keyless decode not run: the event's flag prefix is not known, so a rotation proves nothing"]


def test_text_lines_keep_writing_and_drop_speckle():
    text = "THE LAST LINE\n~~ -- ..\nab\n  fcbbxl{cnv}  \n— = _ - . , ;;\nTHE LAST LINE"
    assert ros.text_lines(text) == ["THE LAST LINE", "fcbbxl{cnv}"]


def test_the_reading_most_sizes_agree_on_comes_first():
    """OCR of ciphertext slips differently at each size. Two sizes read the body right, one does not."""
    arr = _with_plane(_cover(128, 160), 2, 0, _strokes())
    wrong, right = "fcbbxl{cnvagrq_cynar_svkghea}", PORTRAIT_CIPHER       # the last letter of the body misread
    ocr = StubOCR(lambda png, scale: wrong if scale == 1 else right)
    rep = ros.examine({"p.png": _png(arr)}, SFF, prefixes=("spooky",), read=ocr, ledger=False)
    flags = rep.flags()
    assert list(flags) == [PORTRAIT_FLAG, "spooky{painted_plane_fixturn}"]
    reading = next(r for r in rep.readings if r.png is not None)
    assert reading.votes == {PORTRAIT_FLAG: 2, "spooky{painted_plane_fixturn}": 1}
    res = ros.result_of(rep)
    assert res.status == "candidate" and res.flags == (PORTRAIT_FLAG, "spooky{painted_plane_fixturn}")
    again = ros.Report.from_dict(json.loads(json.dumps(rep.to_dict())))   # the saved report keeps the order
    assert list(again.flags()) == list(flags)


# ---- the sweep's order, budget and failures --------------------------------------------------------

@pytest.mark.needs_tool("py:PIL")
def test_planes_are_read_first_then_light_band_pictures_then_dark():
    files = {"a.wav": _whisper(), "p.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}
    ocr = StubOCR()
    rep = ros.examine(files, FF, read=ocr, ledger=False)
    by_png = {r.png: r for r in rep.readings if r.png is not None}
    kinds = []
    for png, _scale in ocr.calls:
        r = by_png[png]
        kinds.append("plane" if r.probe == ros.PROBE_PLANE else r.where.rsplit(", ", 1)[1])
    assert set(kinds) == {"plane", "light", "dark"}
    assert kinds == sorted(kinds, key=("plane", "light", "dark").index)
    assert all(r.state == ros.READ for r in by_png.values()) and rep.ocr == "run"
    assert ros.result_of(rep).status == "none"                           # everything read, nothing written in it


def test_past_the_deadline_renderings_are_named_unread_and_written(tmp_path):
    ocr = StubOCR()
    rep = ros.examine({"p.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}, FF, read=ocr,
                      deadline=time.monotonic() - 1.0, out_dir=tmp_path / "out", ledger=False)
    assert ocr.calls == []
    r = next(x for x in rep.readings if x.png is not None)
    assert r.state == ros.NOT_READ and r.why == "out of time"
    assert rep.skipped == ["OCR: out of time before p.png B bit 0 and what follows it"]
    assert [p.name for p in rep.written] == ["p.png.bitplane-ocr.B_bit_0.png"] and rep.written[0].read_bytes() == r.png
    res = ros.result_of(rep)
    assert res.status == "unsure" and "out of time" in res.notes
    item = next(i for i in ros.checklist(rep) if i["probe"] == ros.PROBE_PLANE)
    assert item["result"] == "error" and item["evidence"].endswith("not run: out of time")   # never 'ruled out'


def test_ocr_off_reads_nothing_and_says_so():
    ocr = StubOCR()
    rep = ros.examine({"p.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}, FF, read=ocr, ocr="off",
                      ledger=False)
    assert ocr.calls == [] and rep.ocr == "off"
    assert next(r for r in rep.readings if r.png is not None).why == "OCR is off"
    assert "OCR off" in ros.result_of(rep).notes
    with pytest.raises(ros.OptionError, match="ocr must be auto, on or off"):
        ros.examine({}, FF, ocr="maybe")
    with pytest.raises(ros.OptionError, match="neither a shift"):          # before any file is read
        ros.examine({"p.png": b"not even looked at"}, FF, keys=["26"])


def test_missing_tesseract_with_something_to_read_is_blocked_by_name(tmp_path, monkeypatch):
    _no_tesseract(monkeypatch)
    (tmp_path / "plate.png").write_bytes(_png(_with_plane(_cover(128, 160), 2, 0, _strokes())))
    res = ros.solve(tmp_path, PROFILE, seconds=LONG, ledger="off")
    assert res.status == "blocked" and "tesseract is not on PATH" in res.notes and not res.flags
    written = tmp_path / "recon" / "render_ocr_sweep" / "plate.png.bitplane-ocr.B_bit_0.png"
    assert written.is_file() and "written for a human or model read" in res.notes
    # nothing drawn anywhere: tesseract was never needed, so its absence blocks nothing
    quiet = tmp_path / "quiet"
    quiet.mkdir()
    (quiet / "noise.png").write_bytes(_png(_cover(128, 160)))
    assert ros.solve(quiet, PROFILE, seconds=LONG, ledger="off").status == "none"


def test_one_failing_ocr_call_is_named_and_the_rest_are_still_read():
    arr = _with_plane(_with_plane(_cover(128, 160), 2, 0, _strokes()), 0, 1, _strokes())
    state = {"n": 0}

    def answer(png, scale):
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("tesseract exited 1: boom")
        return "CSCTF{second_plane}"

    rep = ros.examine({"p.png": _png(arr)}, FF, prefixes=("CSCTF",), read=StubOCR(answer), ledger=False)
    drawn = [r for r in rep.readings if r.png is not None]
    assert [(r.where, r.state) for r in drawn] == [("R bit 1", ros.READ), ("B bit 0", ros.NOT_READ)]   # bit 0 went first
    assert rep.skipped == ["OCR failed on p.png B bit 0: tesseract exited 1: boom"]
    assert list(rep.flags()) == ["CSCTF{second_plane}"]
    item = next(i for i in ros.checklist(rep) if i["probe"] == ros.PROBE_PLANE)
    assert item["result"] == "positive" and item["payload"] == "CSCTF{second_plane}"
    state["n"] = 0
    quiet = ros.examine({"p.png": _png(arr)}, FF, prefixes=("CSCTF",), ledger=False,
                        read=StubOCR(lambda png, scale: answer(png, scale) and ""))
    item = next(i for i in ros.checklist(quiet) if i["probe"] == ros.PROBE_PLANE)
    assert item["result"] == "inconclusive" and "1 of 9 not read" in item["evidence"]      # one read, one not


def test_an_ocr_call_that_runs_out_of_budget_is_named():
    def answer(png, scale):
        raise ic.OutOfBudget("tesseract --psm 6 stopped after 0.1 s")
    rep = ros.examine({"p.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}, FF, read=StubOCR(answer),
                      ledger=False, deadline=time.monotonic() + LONG)
    r = next(x for x in rep.readings if x.png is not None)
    assert r.state == ros.NOT_READ and r.why == "out of time: tesseract --psm 6 stopped after 0.1 s" and not r.partial
    assert rep.skipped == ["OCR: out of time in p.png B bit 0: tesseract --psm 6 stopped after 0.1 s"]
    assert ros.result_of(rep).status == "unsure"
    # one tesseract call stopped at its own limit with the run's deadline still ahead: the run was cut all the same
    assert rep.out_of_time
    whole = ros.examine({"p.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}, FF, read=StubOCR(),
                        ledger=False, deadline=time.monotonic() + LONG)
    assert not whole.out_of_time and whole.skipped == []


def test_the_keyless_decode_out_of_time_still_reads_what_needs_no_decoder():
    skipped = []
    got = ros.text_flags("CSCTF{as_it_stands}\n" + ros.caesar("CSCTF{rotated}", 3), FF, ("CSCTF",),
                         deadline=time.monotonic() - 1.0, skipped=skipped)
    assert dict(got) == {"CSCTF{as_it_stands}": (), "CSCTF{rotated}": ("caesar+23",)}
    assert skipped == ["keyless decode: out of time before every line was read"]


def test_a_recording_over_a_minute_says_what_the_glyph_reader_did_not_see():
    rep = ros.examine({"long.wav": _wav(np.zeros(61 * RATE))}, FF, ocr="off", ledger=False)
    assert "long.wav: the exact 5x7 glyph reader looked at the first 60 s only" in rep.skipped
    spans = {r.where.split(", ")[1] for r in rep.readings if r.probe == ros.PROBE_SPEC}
    assert "0.0-20.0 s" in spans and "41.0-61.0 s" in spans
    short = ros.examine({"short.wav": _wav(np.zeros(2 * RATE))}, FF, ocr="off", ledger=False)
    assert short.skipped == []


# ---- keys from sibling files -----------------------------------------------------------------------

def test_caesar_and_vigenere():
    assert ros.caesar("Khoor, Zruog!", 23) == "Hello, World!"
    assert ros.caesar(ros.caesar("Mixed Case 123", 9), -9) == "Mixed Case 123"
    assert ros.vigenere("LXFOPV EF RNHR", "LEMON") == "ATTACK AT DAWN"
    assert ros.vigenere("ATTACK AT DAWN", "lemon", 1) == "LXFOPV EF RNHR"
    assert ros.vigenere("abc", "123") == "abc"                              # no letters in the key: unchanged
    assert ros.mask("LEMONADE") == "L***(8)"


def test_given_keys_are_validated():
    ks = ros.given_keys(["18", 3, "Lemon"])
    assert [k.value for k in ks] == [18, 3, "Lemon"] and all(k.listed for k in ks)
    for bad in ("26", "0", "two words", "x", "1.5"):
        with pytest.raises(ValueError, match="neither a shift"):
            ros.given_keys([bad])


def test_note_keys_take_the_numbers_of_a_sibling_lsb_note():
    files = {"files/portrait.png": _lsb_note(SIBLING_NOTE), "files/x.txt": b"shift 7"}
    keys = ros.note_keys(files, SFF)
    assert [k.value for k in keys] == [2, 18] and all(k.file == "files/portrait.png" for k in keys)
    assert "the number 18 in files/portrait.png (lsb:" in keys[1].source
    assert ros.note_keys({"files/plain.png": _png(_cover(64, 96))}, SFF) == []


def test_a_shift_from_one_file_is_applied_to_the_text_of_another():
    """The phasmophobia shape: the ciphertext in the recording, the Caesar key in the picture's LSB note."""
    files = {"files/whisper.wav": _wav(_glyph_samples(ros.caesar(LEAD, -18), 9000, 250, 40)),
             "files/portrait.png": _lsb_note(SIBLING_NOTE)}
    rep = ros.examine(files, SFF, prefixes=("spooky",), read=StubOCR(), ledger=False)   # every picture read: nothing in it
    assert rep.keys == [k.source for k in ros.note_keys(files, SFF)] and len(rep.keys) == 2
    plain = [k for k in rep.keyed if k["text"] == LEAD]
    assert len(plain) == 1 and plain[0]["file"] == "files/whisper.wav"
    assert plain[0]["how"].startswith("caesar +18 (the number 18 in files/portrait.png")
    assert {k["how"].split(" (")[0] for k in rep.keyed} == {"caesar +2", "caesar -2", "caesar +18", "caesar -18"}
    res = ros.result_of(rep)
    assert res.status == "unsure" and not res.flags                         # no flag shape: a lead, listed
    assert "keyed reading of files/whisper.wav: caesar +18" in res.notes and LEAD in res.notes
    item = next(i for i in ros.checklist(rep) if i["probe"] == ros.PROBE_KEYS)
    assert item["result"] == "negative" and "2 keys tried" in item["evidence"]
    # the same delivery with the band pictures left unread (OCR off): the join is not ruled out
    unread = ros.examine(files, SFF, prefixes=("spooky",), ocr="off", ledger=False)
    item = next(i for i in ros.checklist(unread) if i["probe"] == ros.PROBE_KEYS)
    assert item["result"] == "inconclusive" and "not ruled out: " in item["evidence"] and "OCR is off" in item["evidence"]


def test_a_key_is_not_applied_to_the_text_of_its_own_file():
    files = {"a.png": _lsb_note(b"the shift is 3, of course")}
    rep = ros.Report()
    same = ros.Reading("a.png", ros.PROBE_PLANE, "B bit 0", text="KHOOR ZRUOG")
    ros._keyed(files, FF, ("CSCTF",), [same], rep, (), None, False)
    assert rep.keys and rep.keyed == []
    rep = ros.Report()
    other = ros.Reading("b.wav", ros.PROBE_GLYPH, "tones", text="KHOOR ZRUOG")
    ros._keyed(files, FF, ("CSCTF",), [other], rep, (), None, False)
    assert [k["text"] for k in rep.keyed] == ["NKRRU CUXRJ", "HELLO WORLD"]


def test_keys_are_tried_once_each_and_the_listing_is_capped():
    files = {"a.wav": _wav(_glyph_samples("KHOOR", 5000, 250, 40)), "p.png": _lsb_note(b"shift by 18, then 18 again")}
    rep = ros.examine(files, FF, prefixes=("CSCTF",), ocr="off", ledger=False, keys=["18"])
    assert rep.keys == ["the given shift 18"]                                 # the note's 18 is the same key
    assert [k["text"] for k in rep.keyed] == ["CZGGJ", "SPWWZ"]
    many = ros.examine(files, FF, prefixes=("CSCTF",), ocr="off", ledger=False, keys=[str(k) for k in range(1, 26)])
    assert len(many.keys) == 25 and len(many.keyed) == ros.MAX_KEYED


def test_a_given_key_reaches_a_flag_no_rotation_search_would():
    cipher = ros.vigenere("CSCTF{GIVEN_KEY}", "PUMPKIN", 1)
    files = {"a.wav": _wav(_glyph_samples(cipher, 5000, 250, 40))}
    without = ros.examine(files, FF, prefixes=("CSCTF",), ocr="off", ledger=False)
    assert not without.flags()
    rep = ros.examine(files, FF, prefixes=("CSCTF",), ocr="off", ledger=False, keys=["pumpkin"])
    assert list(rep.flags()) == ["CSCTF{GIVEN_KEY}"]
    res = ros.result_of(rep)
    assert res.status == "candidate" and "vigenere decrypt (the given key pumpkin)" in res.evidence[0].detail


def test_evidence_ledger_candidates_are_tried_as_keys_and_never_printed():
    """B-068's cross-file join feeds the texts: a password on a sibling shell-history line decrypts the
    recording's text. Its value appears nowhere in the result."""
    cipher = ros.vigenere("SPOOKY{LEDGER_KEY_JOIN}", "LEMONADE", 1)
    files = {"files/whisper.wav": _wav(_glyph_samples(cipher, 9000, 250, 40)),
             "home/.bash_history": b"cd /tmp\nunzip -P LEMONADE secret.zip\nls -la\n"}
    upper = _profile(("SPOOKY",), "b126-upper")
    ff = flagfmt.for_profile(upper)
    rep = ros.examine(files, ff, prefixes=("SPOOKY",), ocr="off")
    assert list(rep.flags()) == ["SPOOKY{LEDGER_KEY_JOIN}"] and rep.keys == ["evidence-ledger candidate L***(8)"]
    res = ros.result_of(rep)
    assert res.status == "candidate" and "LEMONADE" not in res.to_json()
    assert "LEMONADE" not in json.dumps(rep.to_dict())
    assert all(k["flags"] for k in rep.keyed)                              # a ledger key's other readings are not listed
    off = ros.examine(files, ff, prefixes=("SPOOKY",), ocr="off", ledger=False)
    assert not off.flags() and off.keys == []


def test_a_ledger_that_cannot_be_read_is_a_named_note_not_a_silent_skip(monkeypatch):
    def boom(files, deadline=None):
        raise ValueError("the delivery is over 1 bytes")
    monkeypatch.setattr(ros, "ledger_keys", boom)
    rep = ros.examine({"a.wav": _wav(_glyph_samples("CSCTF{A1}", 5000, 250, 40))}, FF, prefixes=("CSCTF",), ocr="off")
    assert rep.key_notes == ["evidence-ledger keys not read: the delivery is over 1 bytes"]
    assert "evidence-ledger keys not read" in ros.result_of(rep).notes
    item = next(i for i in ros.checklist(rep) if i["probe"] == ros.PROBE_KEYS)
    assert item["result"] == "inconclusive"                                  # not ruled out: it did not run


# ---- the checklist and the hypothesis ledger -------------------------------------------------------

def _two_file_report(answer=lambda png, scale: f"THE LAST LINE IS ROT13\n{PORTRAIT_CIPHER}"):
    rng = np.random.default_rng(3)
    files = {"a.wav": _wav(rng.normal(0, 0.05, 3 * RATE)),
             "b.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}
    return ros.examine(files, SFF, prefixes=("spooky",), read=StubOCR(answer), ledger=False)


def test_checklist_is_fixed_and_says_what_was_ruled_out():
    items = ros.checklist(_two_file_report())
    assert [(i["probe"], i["file"], i["result"]) for i in items] == [
        (ros.PROBE_SPEC, "a.wav", "negative"),
        (ros.PROBE_GLYPH, "a.wav", "negative"),
        (ros.PROBE_PLANE, "b.png", "negative"),          # read, and no flag as it stands: the decode found it
        (ros.PROBE_DECODE, None, "positive"),
        (ros.PROBE_KEYS, None, "negative"),
    ]
    assert [i["method"] for i in items] == [
        "toolkits.render_ocr_sweep spectrogram-ocr a.wav", "toolkits.render_ocr_sweep spectrogram-5x7 a.wav",
        "toolkits.render_ocr_sweep bitplane-ocr b.png", "toolkits.render_ocr_sweep keyless-decode",
        "toolkits.render_ocr_sweep cross-file-keys"]
    assert items[3]["payload"] == PORTRAIT_FLAG
    assert "read 0 to 22050 Hz of 22050 Hz (Nyquist)" in items[0]["evidence"] and "blank" in items[0]["evidence"]
    assert "THE LAST LINE IS ROT13" in items[2]["evidence"]
    assert items[4]["evidence"].startswith("no key hint in any sibling file")
    nothing = ros.checklist(_two_file_report(lambda png, scale: ""))
    assert [i["result"] for i in nothing] == ["negative"] * 5
    assert nothing[3]["evidence"] == "no text was read, so there was nothing to decode"


def test_checklist_marks_the_rejected_reading_and_keeps_another_flag_open():
    rep = _two_file_report()
    items = ros.checklist(rep, rejected=PORTRAIT_FLAG)
    assert [i["result"] for i in items] == ["negative", "negative", "negative", "false_positive", "negative"]
    assert items[3]["payload"] == PORTRAIT_FLAG and "was rejected" in items[3]["evidence"]
    text = ros.checklist_text(items, PORTRAIT_FLAG)
    assert text.splitlines()[0] == f"render_ocr_sweep checklist after the rejection of {PORTRAIT_FLAG}:"
    assert "[REJECTED  ] keyless-decode" in text and "[ruled out ] bitplane-ocr     b.png" in text
    assert all(f"  - {x}" in text for x in ros.NOT_COVERED)
    two = _two_file_report(lambda png, scale: f"{PORTRAIT_CIPHER}\nfcbbxl{{nabgure_bar}}")
    items = ros.checklist(two, rejected=PORTRAIT_FLAG)
    assert items[3]["result"] == "positive" and items[3]["payload"] == "spooky{another_one}"
    unrelated = ros.checklist(rep, rejected="spooky{never_read_here}")
    assert unrelated[3]["result"] == "positive"                              # not ours to mark


def test_checklist_never_calls_an_unread_probe_ruled_out(monkeypatch):
    _no_tesseract(monkeypatch)
    rep = ros.examine({"b.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}, SFF, ledger=False)
    item = ros.checklist(rep)[0]
    assert item["result"] == "error" and item["evidence"].endswith("not run: tesseract is not on PATH")
    text = ros.checklist_text(ros.checklist(rep))
    assert "[not run   ] bitplane-ocr" in text and "ruled out ] bitplane-ocr" not in text


def test_file_checklist_writes_negatives_and_the_false_positive(tmp_path):
    rep = _two_file_report()
    cid = "42"
    first = ros.file_checklist(cid, ros.checklist(rep), workdir=tmp_path, profile=SPOOKY)
    assert [r["result"] for r in first] == ["negative", "negative", "negative", "positive", "negative"]
    assert first[3]["verified"] and first[3]["payload"] == PORTRAIT_FLAG and first[3]["agent"] == ros.ENGINE
    plane = ros.method_of(ros.PROBE_PLANE, "b.png")
    decode = ros.method_of(ros.PROBE_DECODE)
    assert hyp.should_skip(cid, plane, tmp_path).skip                       # ruled out: not run again
    assert hyp.seen(cid, ros.method_of(ros.PROBE_SPEC, "a.wav"), tmp_path)["result"] == hyp.NEGATIVE
    # the platform rejects the flag: the reading is corrected, not re-derived
    second = ros.file_checklist(cid, ros.checklist(rep, rejected=PORTRAIT_FLAG), workdir=tmp_path, profile=SPOOKY)
    assert [r["result"] for r in second] == ["negative", "negative", "negative", "false_positive", "negative"]
    assert hyp.seen(cid, decode, tmp_path)["result"] == hyp.FALSE_POSITIVE
    skip = hyp.should_skip(cid, decode, tmp_path)
    assert skip.skip and "false_positive" in skip.reason
    assert hyp.mine(cid, tmp_path) is None                                  # no mechanism is claimed any more
    assert sum(r["result"] == hyp.POSITIVE for r in hyp.entries(cid, tmp_path)) == 1


def test_a_rejection_filed_first_still_has_a_positive_to_correct(tmp_path):
    rep = _two_file_report()
    recs = ros.file_checklist("7", ros.checklist(rep, rejected=PORTRAIT_FLAG), workdir=tmp_path, profile=SPOOKY)
    assert [r["result"] for r in recs] == ["negative", "negative", "negative", "positive", "false_positive", "negative"]
    assert recs[3]["payload"] == PORTRAIT_FLAG and recs[3]["evidence"] == "the reading the platform then rejected"
    assert hyp.seen("7", ros.method_of(ros.PROBE_DECODE), tmp_path)["result"] == hyp.FALSE_POSITIVE


def test_a_rejection_after_a_negative_on_the_same_method_still_files_its_positive(tmp_path):
    """A first run read nothing in the plane and filed the decode as ruled out; a later run decoded a flag
    and the platform rejected it. The latest record on the method is a negative, not a positive: the
    rejected reading must still be filed as a positive before its correction."""
    decode = ros.method_of(ros.PROBE_DECODE)
    ros.file_checklist("8", ros.checklist(_two_file_report(lambda png, scale: "")), workdir=tmp_path, profile=SPOOKY)
    assert hyp.seen("8", decode, tmp_path)["result"] == hyp.NEGATIVE
    recs = ros.file_checklist("8", ros.checklist(_two_file_report(), rejected=PORTRAIT_FLAG), workdir=tmp_path,
                              profile=SPOOKY)
    assert [r["result"] for r in recs] == ["negative", "negative", "negative", "positive", "false_positive", "negative"]
    assert recs[3]["payload"] == PORTRAIT_FLAG and hyp.seen("8", decode, tmp_path)["result"] == hyp.FALSE_POSITIVE


def test_an_unread_probe_is_filed_as_not_settled(tmp_path, monkeypatch):
    _no_tesseract(monkeypatch)
    rep = ros.examine({"b.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}, SFF, ledger=False)
    ros.file_checklist("9", ros.checklist(rep), workdir=tmp_path, profile=SPOOKY)
    method = ros.method_of(ros.PROBE_PLANE, "b.png")
    assert hyp.seen("9", method, tmp_path)["result"] == hyp.ERROR
    assert not hyp.should_skip("9", method, tmp_path).skip                  # worth running once tesseract is there


# ---- the engine contract ---------------------------------------------------------------------------

def _glyph_challenge(root: Path, flag="CSCTF{GLYPH_FLAG}", cid=None) -> Path:
    d = root / "101-tones"
    (d / "files").mkdir(parents=True)
    (d / "files" / "tones.wav").write_bytes(_wav(_glyph_samples(flag, 9000, 250, 40)))
    if cid is not None:
        (d / "challenge.json").write_text(json.dumps({"id": cid, "name": "tones"}))
    return d


def test_solve_saves_a_report_that_is_reused_only_for_the_same_files(tmp_path):
    d = _glyph_challenge(tmp_path)
    res = ros.solve(d, PROFILE, seconds=LONG, ocr="off", ledger="off")
    assert res.flags == ("CSCTF{GLYPH_FLAG}",) and res.challenge_id is None
    out = ros.default_out(d)
    assert out == d / "recon" / "render_ocr_sweep" and (out / "report.json").is_file()
    assert any(e.detail == "report written" and e.path == "recon/render_ocr_sweep/report.json" for e in res.evidence)
    saved = ros.load_report(out, ic.challenge_files(d))
    assert saved is not None and list(saved.flags()) == ["CSCTF{GLYPH_FLAG}"]
    live = ros.sweep(d, PROFILE, seconds=LONG, ocr="off", ledger="off")
    assert ros.checklist(saved) == ros.checklist(live)                      # nothing the checklist needs is lost
    (d / "files" / "tones.wav").write_bytes(_wav(_glyph_samples("CSCTF{OTHER}", 9000, 250, 40)))
    assert ros.load_report(out, ic.challenge_files(d)) is None              # the files changed: not reused
    with pytest.raises(ValueError, match="not a toolkits.render_ocr_sweep report"):
        ros.Report.from_dict({"schema": 99, "engine": ros.ENGINE})


def test_solve_record_writes_the_checklist_to_the_hypothesis_ledger(tmp_path):
    d = _glyph_challenge(tmp_path, cid=101)
    wd = tmp_path / "work"
    res = ros.solve(d, PROFILE, seconds=LONG, ocr="off", ledger="off", record="1", workdir=str(wd))
    assert res.status == "solved" and res.challenge_id == "101"
    got = hyp.seen("101", ros.method_of(ros.PROBE_GLYPH, "files/tones.wav"), wd)
    assert got["result"] == hyp.POSITIVE and got["payload"] == "CSCTF{GLYPH_FLAG}" and got["verified"]
    spec = hyp.seen("101", ros.method_of(ros.PROBE_SPEC, "files/tones.wav"), wd)
    assert spec["result"] == hyp.ERROR and "OCR is off" in spec["evidence"]      # not read is not ruled out
    # with no id anywhere, recording is refused by name instead of writing to a made-up ledger
    bare = _glyph_challenge(tmp_path / "bare")
    blocked = ros.solve(bare, PROFILE, seconds=LONG, ocr="off", ledger="off", record="1", workdir=str(wd))
    assert blocked.status == "blocked" and "no challenge id" in blocked.notes
    assert ros.solve(d, PROFILE, seconds=LONG, ocr="off", ledger="off").challenge_id == "101"
    for bad in ({"keys": ["two words"]}, {"ocr": "maybe"}, {"seconds": "soon"}, {"top_hz": "high"}, {"ledger": "maybe"}):
        res = ros.solve(d, PROFILE, **{"ocr": "off", **bad})
        assert res.status == "blocked" and res.notes.startswith("bad option: "), bad
    assert not (bare / "recon").exists()                                    # refused before anything was read
    capped = ros.solve(d, PROFILE, seconds=LONG, ocr="off", ledger="off", top_hz="8000")   # options arrive as text
    assert "read only to 8000 Hz (top_hz); 8000 to 22050 Hz was not looked at" in capped.notes


def test_main_prints_the_checklist_and_the_result_json_last(tmp_path, capsys):
    f = tmp_path / "tones.wav"
    f.write_bytes(_wav(_glyph_samples("SPOOKY{CLI_PATH}", 9000, 250, 40)))
    assert ros.main([str(f), "--event", "spooky", "--ocr", "off", "--seconds", str(LONG)]) == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert out[0] == "render_ocr_sweep checklist:" and any("[open      ] spectrogram-5x7" in x for x in out)
    last = json.loads(out[-1])
    assert last["status"] == "solved" and last["flags"] == ["SPOOKY{CLI_PATH}"] and last["engine"] == ros.ENGINE
    assert ros.main([str(tmp_path / "missing.wav"), "--event", "spooky"]) == 2
    assert ros.main([str(f), "--event", "spooky", "--ocr", "off", "--key", "0"]) == 2


# ---- routing and intake ----------------------------------------------------------------------------

def test_wav_and_images_route_here_in_any_category(tmp_path):
    from ctf.engines import router
    (tmp_path / "song.wav").write_bytes(_wav(np.zeros(2000)))
    assert ros.ENGINE in [h.manifest.id for h in router.route("misc", "Operation Dawn", tmp_path)]
    pics = tmp_path / "pics"
    pics.mkdir()
    (pics / "plate.png").write_bytes(_png(_cover(8, 8)))
    ids = [h.manifest.id for h in router.route("misc", "Operation Dawn", pics)]
    assert ros.ENGINE in ids and ids.index("toolkits.image_carve") < ids.index(ros.ENGINE)
    other = tmp_path / "other"
    other.mkdir()
    (other / "notes.txt").write_text("plain words")
    assert ros.ENGINE not in [h.manifest.id for h in router.route("misc", "Operation Dawn", other)]
    ids = [h.manifest.id for h in router.route("stego", "something whispering in the spectrogram", other)]
    assert ros.ENGINE in ids


@pytest.mark.needs_tool("tesseract", "py:PIL")
def test_intake_runs_the_engine_on_a_picture_with_no_model(tmp_path):
    from ctf.engines import manifest
    from ctf.intake import engines as E
    from ctf.intake import guard as G
    ms = manifest.discover()
    cd = tmp_path / "77-portrait"
    (cd / "unpacked").mkdir(parents=True)
    (cd / "unpacked" / "portrait.png").write_bytes(_portrait())
    allow = G.Guard("os", (), "test: spawn allowed, no OS wrapper (the suite sandbox denies the network)")
    p = E.plan(ms, "misc", "an old portrait", cd / "unpacked", guard=allow)
    job = next(j for j in p.jobs if j.engine == ros.ENGINE)
    assert job.manifest.intake.run == "challenge" and job.manifest.intake.spawns
    hook = E.plan(ms, "misc", "an old portrait", cd / "unpacked", guard=G.Guard("hook", (), "test"))
    assert ros.ENGINE in {s.engine for s in hook.skipped}                  # it starts tesseract: os guard only
    ctx = E.Context(challenge_dir=cd, folder=cd / "unpacked", out_root=cd / "recon" / "engines",
                    profile=event.load("spooky"), guard=allow, root=REPO, python=sys.executable,
                    challenge_id="77", record=False)
    run = E.run_job(job, ctx)
    assert run.status == "ok", (cd / run.errors).read_text()
    assert run.result_status == "candidate" and run.flags[0] == PORTRAIT_FLAG
    assert (cd / "recon" / "render_ocr_sweep" / "unpacked_portrait.png.bitplane-ocr.B_bit_0.png").is_file()


# ---- the checklist CLI -----------------------------------------------------------------------------

def _cli(*argv):
    from ctf.cli import render_sweep as mod
    p = argparse.ArgumentParser()
    mod.add_arguments(p)
    return mod.run(p.parse_args(list(argv)))


def test_cli_checklist_prints_and_records_only_when_asked(tmp_path, capsys):
    d = _glyph_challenge(tmp_path, flag="SPOOKY{CLI_FLAG}", cid="55")
    wd = tmp_path / "work"
    assert _cli("--event", "spooky", "--workdir", str(wd), "checklist", str(d), "--ocr", "off", "--seconds", str(LONG)) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "(fresh sweep)" and "[open      ] spectrogram-5x7  files/tones.wav" in out
    assert "[not run   ] spectrogram-ocr  files/tones.wav" in out and "OCR is off" in out
    assert "not covered by this sweep:" in out and "recorded" not in out
    assert not (wd / "hypotheses").exists()
    assert _cli("--event", "spooky", "--workdir", str(wd), "checklist", str(d), "--ocr", "off", "--record", "--json") == 0
    got = json.loads(capsys.readouterr().out)
    assert got["source"] == "saved report" and got["recorded"] == 4 and got["rejected"] is None
    assert [i["probe"] for i in got["items"]] == [ros.PROBE_SPEC, ros.PROBE_GLYPH, ros.PROBE_DECODE, ros.PROBE_KEYS]
    assert hyp.seen("55", ros.method_of(ros.PROBE_GLYPH, "files/tones.wav"), wd)["result"] == hyp.POSITIVE


def test_cli_rejected_files_the_false_positive_under_the_challenge_id(tmp_path, capsys):
    d = _glyph_challenge(tmp_path, flag="SPOOKY{CLI_FLAG}", cid="55")
    wd = tmp_path / "work"
    args = ("--event", "spooky", "--workdir", str(wd), "rejected", str(d), "--flag", "SPOOKY{CLI_FLAG}", "--ocr", "off",
            "--seconds", str(LONG))
    assert _cli(*args) == 0
    out = capsys.readouterr().out
    assert "after the rejection of SPOOKY{CLI_FLAG}" in out and "[REJECTED  ] spectrogram-5x7" in out
    assert "recorded 5 hypothesis-ledger lines" in out                       # 4 items, the rejected one as two lines
    method = ros.method_of(ros.PROBE_GLYPH, "files/tones.wav")
    assert hyp.seen("55", method, wd)["result"] == hyp.FALSE_POSITIVE and hyp.should_skip("55", method, wd).skip
    assert _cli(*args, "--cid", "other-id") == 0                             # --cid wins over challenge.json
    assert "(saved report)" in capsys.readouterr().out
    assert hyp.seen("other-id", method, wd)["result"] == hyp.FALSE_POSITIVE
    assert _cli(*args, "--fresh") == 0
    assert "(fresh sweep)" in capsys.readouterr().out
    assert _cli("--event", "spooky", "--workdir", str(wd), "rejected", str(d), "--flag", "spooky{not_ours}",
                "--ocr", "off") == 0
    assert "no reading of this sweep gave spooky{not_ours}; nothing was marked rejected" in capsys.readouterr().out


def test_cli_named_errors_exit_2(tmp_path, capsys):
    bare = _glyph_challenge(tmp_path)                                        # no challenge.json
    wd = tmp_path / "work"
    assert _cli("--event", "spooky", "--workdir", str(wd), "rejected", str(bare), "--flag", "x", "--ocr", "off") == 2
    assert "no challenge id: pass --cid" in capsys.readouterr().err
    assert not (wd / "hypotheses").exists()
    assert _cli("--event", "spooky", "checklist", str(tmp_path / "nowhere")) == 2
    assert "no such challenge folder" in capsys.readouterr().err
    assert _cli("--event", "no-such-event", "checklist", str(bare)) == 2
    assert "no-such-event" in capsys.readouterr().err
    assert _cli("--event", "spooky", "checklist", str(bare), "--fresh", "--ocr", "off", "--key", "two words") == 2
    assert "neither a shift" in capsys.readouterr().err


def test_cli_ocr_on_without_tesseract_exits_2(tmp_path, capsys, monkeypatch):
    _no_tesseract(monkeypatch)
    d = _glyph_challenge(tmp_path)
    assert _cli("--event", "spooky", "checklist", str(d), "--ocr", "on", "--seconds", str(LONG)) == 2
    assert "tesseract is not on PATH" in capsys.readouterr().err


# ---- the survey row --------------------------------------------------------------------------------

def test_survey_reads_the_render_sweep_first_even_with_the_sandbox_down(monkeypatch):
    import stego_tools as st
    monkeypatch.setattr(st, "exif", lambda data, name="file": st.Rec(note="sandbox down: stub", tool="exiftool"))
    _no_tesseract(monkeypatch)
    rows = st.survey("tones.wav", _wav(_glyph_samples("CSCTF{SURVEY_ROW}", 9000, 250, 40)))
    assert [what for what, _rec in rows] == ["render sweep (spectrogram to Nyquist, bit planes 0-2)", "exiftool"]
    rec = rows[0][1]
    assert rec.ok and rec.tool == "render_ocr_sweep" and "CSCTF{SURVEY_ROW}" in rec.text
    assert rec.text.splitlines()[0] == "FLAG CSCTF{SURVEY_ROW}"            # conftest's event is csctf
    assert rec.files and all(v.startswith(ic.PNG_SIG) for v in rec.files.values())
    assert "tesseract is not on PATH" in rec.note
    from PIL import Image
    buf = io.BytesIO()
    Image.fromarray(_cover(32, 32)).save(buf, "JPEG")
    assert [what for what, _rec in st.survey("a.jpg", buf.getvalue())] == ["exiftool"]
    monkeypatch.setattr(st, "on_timed_path", lambda: True)                  # a timed window: nothing slow is run
    timed = st.render_sweep("tones.wav", _wav(np.zeros(2000)))
    assert not timed.ok and timed.note == "on a timed path: not run"


def test_survey_read_of_a_plane_lists_its_renderings():
    got = ros.survey_read("p.png", _png(_with_plane(_cover(128, 160), 2, 0, _strokes())), seconds=LONG)
    assert list(got["files"]) == ["B_bit_0.png"] and got["data"]["files"]["p.png"]["kind"] == "image"
    assert got["note"].startswith("render_ocr_sweep: ")
    assert ros.survey_read("x.bin", b"\x00" * 64)["ok"] is False


# ---- verification round 1: what the clock stops is never ruled out ---------------------------------

class HeldClock:
    """The engine's clock for a run the deadline cuts part way: the real monotonic clock, held `back`
    seconds until the test lets it go. Only render_ocr_sweep reads it; the readers it calls (carve_stego,
    the evidence ledger) keep the real clock. So a deadline already past in real time is still ahead for
    the engine until `back` is set to 0, and no test waits on, or races, real time."""

    def __init__(self, back=1e6):
        self.back = back

    def monotonic(self):
        return time.monotonic() - self.back


def test_a_glyph_read_the_clock_stopped_is_not_read_never_blank(monkeypatch):
    samples = _glyph_samples("CSCTF{GLYPH}", 9000, 250, 40)
    audio = sd.Audio(RATE, samples)
    stopped = []
    assert [t for t, _ in ros.glyph_text(audio, time.monotonic() + LONG, stopped)] == ["CSCTF{GLYPH}"] and stopped == []
    assert ros.glyph_text(audio, time.monotonic() - 1.0, stopped) == [] and stopped == [ros.OUT_OF_TIME]
    # the deadline passing inside the search, after the measuring: a step clock, one tick a look
    with monkeypatch.context() as m:
        ticks = iter(range(10 ** 6))
        m.setattr(ros, "time", types.SimpleNamespace(monotonic=lambda: next(ticks)))
        stopped = []
        assert ros.glyph_text(audio, 0.5, stopped) == [] and stopped == [ros.OUT_OF_TIME]
    rep = ros.examine({"a.wav": _wav(samples)}, FF, prefixes=("CSCTF",), read=StubOCR(), ledger=False,
                      deadline=time.monotonic() - 1.0)
    assert [(r.state, r.why) for r in rep.readings if r.probe == ros.PROBE_GLYPH] == [(ros.NOT_READ, "out of time")]
    assert "a.wav: exact 5x7 glyph read: out of time before every arrangement was tried" in rep.skipped
    assert rep.out_of_time and not rep.flags()
    items = {i["probe"]: i for i in ros.checklist(rep)}
    assert items[ros.PROBE_GLYPH]["result"] == "error" and items[ros.PROBE_GLYPH]["evidence"].endswith("not run: out of time")
    # nothing was read, so neither delivery-wide probe is ruled out either
    assert items[ros.PROBE_DECODE]["result"] == "error" and items[ros.PROBE_KEYS]["result"] == "error"
    assert "not ruled out: " in items[ros.PROBE_DECODE]["evidence"] and "out of time" in items[ros.PROBE_DECODE]["evidence"]
    assert "exact 5x7 glyph read: out of time" in ros.result_of(rep).notes
    # with time, the same recording is read and its probe is open
    full = ros.examine({"a.wav": _wav(samples)}, FF, prefixes=("CSCTF",), read=StubOCR(), ledger=False,
                       deadline=time.monotonic() + LONG)
    assert not full.out_of_time and list(full.flags()) == ["CSCTF{GLYPH}"]
    assert [r.state for r in full.readings if r.probe == ros.PROBE_GLYPH] == [ros.READ]


def test_a_decode_or_key_search_the_clock_cut_is_not_ruled_out(monkeypatch):
    files = {"p.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes())),
             "note.png": _lsb_note(b"the shift is 7, of course")}
    words = "PLAIN WORDS ON A PLANE\nAND A SECOND LINE"
    whole = ros.examine(files, FF, prefixes=("CSCTF",), read=StubOCR(lambda png, scale: words), ledger=False,
                        deadline=time.monotonic() + LONG)
    assert whole.decode == "run" and not whole.out_of_time and whole.key_notes == []
    done = {i["probe"]: i for i in ros.checklist(whole)}
    assert done[ros.PROBE_DECODE]["result"] == "negative" and done[ros.PROBE_KEYS]["result"] == "negative"
    assert "1 keys tried (the number 7 in note.png" in done[ros.PROBE_KEYS]["evidence"]
    # the same run with the OCR eating the budget: the pictures are read, the decoder and the key search are not
    clock = HeldClock()
    monkeypatch.setattr(ros, "time", clock)

    def slow(png, scale):
        clock.back = 0.0
        return words

    rep = ros.examine(files, FF, prefixes=("CSCTF",), read=StubOCR(slow), ledger=False, deadline=time.monotonic() - 1.0)
    monkeypatch.undo()
    assert [r.state for r in rep.readings if r.png is not None] == [ros.READ]
    assert rep.decode == "cut: out of time before every line was read" and ros.DECODE_CUT in rep.skipped
    assert rep.keys == [] and len(rep.key_notes) == 1 and rep.out_of_time
    assert rep.key_notes[0].startswith("sibling notes not read to the end (") and "out of time" in rep.key_notes[0]
    items = {(i["probe"], i["file"]): i for i in ros.checklist(rep)}
    assert items[(ros.PROBE_PLANE, "p.png")]["result"] == "negative"         # that one did run to the end
    decode, keys = items[(ros.PROBE_DECODE, None)], items[(ros.PROBE_KEYS, None)]
    assert decode["result"] == "inconclusive"
    assert decode["evidence"].endswith("not ruled out: out of time before every line was read")
    assert keys["result"] == "inconclusive" and "sibling notes not read to the end" in keys["evidence"]
    text = ros.checklist_text(list(items.values()))
    assert "[incomplete] keyless-decode" in text and "[incomplete] cross-file-keys" in text
    # the evidence ledger is not started after the deadline, and says so
    late = ros.Report()
    ros._keyed({}, FF, ("CSCTF",), [ros.Reading("b.wav", ros.PROBE_GLYPH, "tones", text="KHOOR ZRUOG")], late, (),
               time.monotonic() - 1.0, True)
    assert late.key_notes == ["evidence-ledger keys not read: out of time"]


def test_a_cut_checklist_is_filed_as_not_settled(tmp_path, monkeypatch):
    clock = HeldClock()
    monkeypatch.setattr(ros, "time", clock)

    def slow(png, scale):
        clock.back = 0.0
        return "PLAIN WORDS ON A PLANE"

    rep = ros.examine({"p.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}, FF, prefixes=("CSCTF",),
                      read=StubOCR(slow), ledger=False, deadline=time.monotonic() - 1.0)
    monkeypatch.undo()
    ros.file_checklist("12", ros.checklist(rep), workdir=tmp_path, profile=PROFILE)
    decode = ros.method_of(ros.PROBE_DECODE)
    assert hyp.seen("12", decode, tmp_path)["result"] == hyp.INCONCLUSIVE
    assert not hyp.should_skip("12", decode, tmp_path).skip                 # worth running again with more time
    assert hyp.should_skip("12", ros.method_of(ros.PROBE_PLANE, "p.png"), tmp_path).skip


def test_missing_readings_keep_the_delivery_wide_probes_open(monkeypatch):
    arr = _with_plane(_with_plane(_cover(128, 160), 2, 0, _strokes()), 0, 1, _strokes())
    state = {"n": 0}

    def answer(png, scale):
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("tesseract exited 1: boom")
        return "FOUR PLAIN WORDS HERE"

    rep = ros.examine({"p.png": _png(arr)}, FF, prefixes=("CSCTF",), read=StubOCR(answer), ledger=False)
    items = {i["probe"]: i for i in ros.checklist(rep)}
    assert items[ros.PROBE_PLANE]["result"] == "inconclusive"
    for probe in (ros.PROBE_DECODE, ros.PROBE_KEYS):                       # one plane read, one not: not a no
        assert items[probe]["result"] == "inconclusive", probe
        assert "not ruled out: 1 readings were not made (p.png B bit 0: tesseract exited 1: boom)" in items[probe]["evidence"]
    _no_tesseract(monkeypatch)
    none = ros.examine({"p.png": _png(arr)}, FF, prefixes=("CSCTF",), ledger=False)
    assert [i["result"] for i in ros.checklist(none)] == ["error", "error", "error"]
    assert "ruled out ]" not in ros.checklist_text(ros.checklist(none)).split("not covered")[0]


def test_an_unknown_flag_prefix_files_the_decode_as_not_run():
    unknown = flagfmt.for_profile(_profile((), "b126-unknown-2"))
    rep = ros.examine({"p.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}, unknown,
                      read=StubOCR(lambda png, scale: "FOUR PLAIN WORDS HERE"), ledger=False)
    assert rep.decode == f"not run: {ros.NO_PREFIX}"
    item = next(i for i in ros.checklist(rep) if i["probe"] == ros.PROBE_DECODE)
    assert item["result"] == "error" and item["evidence"] == rep.decode       # crib_decode never ran: not a negative


# ---- verification round 1: a saved report answers only the run it was made for ---------------------

def test_a_saved_report_is_reused_only_for_the_same_options(tmp_path):
    d = _glyph_challenge(tmp_path, flag=ros.vigenere("CSCTF{GIVEN_KEY}", "PUMPKIN", 1))
    made = ros.sweep(d, PROFILE, seconds=LONG, ocr="off", ledger="off")
    out, files = ros.default_out(d), ic.challenge_files(d)
    base = dict(ocr="off", prefixes=("CSCTF",), ledger=False)
    same = ros.run_options(FF, **base)
    assert made.options == same and made.seconds == LONG and not made.out_of_time
    saved = ros.load_report(out, files, same)
    assert saved is not None and saved.options == same and saved.seconds == LONG   # the options survive the save
    assert ros.load_report(out, files) is not None                          # asked by files only: as before
    for change, named in (({"keys": ["pumpkin"]}, "keys"), ({"ocr": "auto"}, "ocr"), ({"top_hz": 8000}, "top_hz"),
                          ({"ledger": True}, "ledger"), ({"prefixes": ("CSCTF", "FLAG")}, "prefixes")):
        want = ros.run_options(FF, **{**base, **change})
        assert ros.load_report(out, files, want) is None, named
        assert ros.stale(saved, want) == f"the saved report was made with other options ({named})"
    assert ros.stale(saved, ros.run_options(SFF, **base)) == "the saved report was made with other options (flag)"
    assert ros.stale(saved, same) is None and ros.stale(saved, same, seconds=LONG * 2) is None    # not cut: any budget
    # the options compare as they are applied
    assert ros.run_options(FF, keys=["PUMPKIN", "44"]) == ros.run_options(FF, keys=["18", "pumpkin", "Pumpkin"])
    assert ros.run_options(FF, ocr="on") == ros.run_options(FF, ocr="auto") != ros.run_options(FF, ocr="off")
    with pytest.raises(ros.OptionError, match="neither a shift"):
        ros.run_options(FF, keys=["two words"])
    # the key that was missing is applied by the run the mismatch forces
    keyed = ros.sweep(d, PROFILE, seconds=LONG, ocr="off", ledger="off", keys=["pumpkin"])
    assert list(keyed.flags()) == ["CSCTF{GIVEN_KEY}"] and not made.flags()
    assert ros.load_report(out, files, ros.run_options(FF, **base, keys=["PUMPKIN"])) is not None
    assert ros.load_report(out, files, same) is None                        # and the keyed report is not the keyless answer
    # a report with no options on record (an older build's) answers no run that states its options
    p = out / "report.json"
    data = json.loads(p.read_text())
    del data["options"]
    p.write_text(json.dumps(data))
    assert ros.load_report(out, files, same) is None and ros.load_report(out, files) is not None
    assert ros.stale(ros.load_report(out, files), same) == "the saved report does not record the options it was made with"


def test_a_report_saved_without_tesseract_or_cut_by_the_clock_is_not_reused(tmp_path, monkeypatch):
    (tmp_path / "plate.png").write_bytes(_png(_with_plane(_cover(128, 160), 2, 0, _strokes())))
    out = ros.default_out(tmp_path)
    want = ros.run_options(FF, prefixes=("CSCTF",), ledger=False)

    def files():
        return ic.challenge_files(tmp_path)

    with monkeypatch.context() as m:
        _no_tesseract(m)
        blind = ros.sweep(tmp_path, PROFILE, seconds=LONG, ledger="off")
    assert blind.ocr == "not run: tesseract is not on PATH" and blind.options == want
    assert ros.load_report(out, files(), want) is None                      # tesseract may be there now
    assert ros.stale(blind, want) == "the saved report's OCR was not run: tesseract is not on PATH"
    read = ros.sweep(tmp_path, PROFILE, seconds=LONG, ledger="off", read=StubOCR())
    assert read.ocr == "run" and ros.load_report(out, files(), want, seconds=LONG * 2) is not None
    # a run the clock cut (its budget was already spent when it began) answers only a run with no more time
    cut = ros.sweep(tmp_path, PROFILE, seconds=-1.0, ledger="off", read=StubOCR())
    assert cut.out_of_time and cut.seconds == -1.0
    assert ros.load_report(out, files(), want) is None                      # the engine's default budget is more
    assert ros.load_report(out, files(), want, seconds=5.0) is None
    assert ros.stale(cut, want, seconds=5.0) == "the saved report ran out of time, on a smaller budget than this run has"
    assert ros.load_report(out, files(), want, seconds=-1.0) is not None


def test_cli_applies_a_key_given_after_a_report_was_saved(tmp_path, capsys):
    d = _glyph_challenge(tmp_path, flag=ros.vigenere("SPOOKY{CLI_KEY}", "PUMPKIN", 1), cid="56")
    wd = tmp_path / "work"
    base = ("--event", "spooky", "--workdir", str(wd), "checklist", str(d), "--ocr", "off", "--seconds", str(LONG),
            "--json")

    def keys_item(*more):
        assert _cli(*base, *more) == 0
        got = json.loads(capsys.readouterr().out)
        return got["source"], next(i for i in got["items"] if i["probe"] == ros.PROBE_KEYS)

    source, item = keys_item()
    assert source == "fresh sweep" and item["result"] == "inconclusive" and item["payload"] is None
    source, item = keys_item()
    assert source == "saved report" and item["payload"] is None
    source, item = keys_item("--key", "pumpkin")                             # the key is applied, not ignored
    assert source == "fresh sweep: the saved report was made with other options (keys)"
    assert item["result"] == "positive" and item["payload"] == "SPOOKY{CLI_KEY}"
    source, item = keys_item("--key", "PUMPKIN")                             # the same key: the saved answer
    assert source == "saved report" and item["payload"] == "SPOOKY{CLI_KEY}"
    assert _cli(*base, "--key", "PUMPKIN", "--record") == 0                  # and the ledger gets the keyed reading
    capsys.readouterr()
    assert hyp.seen("56", ros.method_of(ros.PROBE_KEYS), wd)["payload"] == "SPOOKY{CLI_KEY}"
    source, item = keys_item()                                               # without it again: not the keyed report
    assert source.startswith("fresh sweep: ") and item["payload"] is None
    assert _cli("--event", "spooky", "--workdir", str(wd), "checklist", str(d), "--ocr", "off", "--seconds", str(LONG)) == 0
    assert capsys.readouterr().out.splitlines()[0] == "(saved report)"


# ---- verification round 1: routing -----------------------------------------------------------------

def test_everyday_words_do_not_route_a_brief_with_no_media_here(tmp_path):
    from ctf.engines import manifest, router
    (tmp_path / "app.py").write_text("print('hello')\n")
    for cat, brief in (("web", "find the admin's painting"), ("pwn", "the binary will whisper its secrets"),
                       ("osint", "who painted this portrait?"), ("misc", "the flag is hidden inside it"),
                       ("forensics", "something is hidden in the audio")):
        assert ros.ENGINE not in [h.manifest.id for h in router.route(cat, brief, tmp_path)], brief
    for brief in ("read the spectrogram", "look at every bit plane", "a bitplane puzzle", "the bit-plane trick"):
        assert ros.ENGINE in [h.manifest.id for h in router.route("misc", brief, tmp_path)], brief
    mine = next(m for m in manifest.discover() if m.id == ros.ENGINE)
    assert sorted(k for r in mine.routes for k in r.keywords) == ["bit plane", "bit-plane", "bitplane", "spectrogram"]
    # with a picture in the folder a web brief still reaches it, by the file route and after the image engines
    (tmp_path / "logo.png").write_bytes(_png(_cover(8, 8)))
    ids = [h.manifest.id for h in router.route("web", "find the admin's painting", tmp_path)]
    assert ros.ENGINE in ids and ids.index("toolkits.image_carve") < ids.index(ros.ENGINE)


# ---- verification round 1: the mutations that survived ---------------------------------------------

def test_a_mark_under_200_ink_cells_is_blank_whatever_its_share():
    """A 50 ms blip in a 3 s recording is over 0.1% of every band picture that holds it, and still far
    less ink than one glyph: the cell floor, not the share, is what keeps it from OCR."""
    rng = np.random.default_rng(8)
    t = np.arange(3 * RATE) / RATE
    fade = np.clip((t - 2.0) / 0.01, 0, 1) * np.clip((2.05 - t) / 0.01, 0, 1)
    rs = ros.renderings(sd.Audio(RATE, rng.normal(0, 0.002, t.size) + 0.3 * np.sin(2 * np.pi * 9500 * t) * fade))
    assert all(r.blank and r.png is None for r in rs)
    inked = [r for r in rs if r.ink >= 2 * ros.BLANK]
    assert len(inked) >= 2 and all(r.lo <= 9500 <= r.hi for r in inked)


def test_two_distinct_flags_are_candidates_even_when_one_is_exact():
    wav = _wav(_glyph_samples("CSCTF{EXACT_ONE}", 9000, 250, 40))
    alone = ros.result_of(ros.examine({"a.wav": wav}, FF, prefixes=("CSCTF",), read=StubOCR(), ledger=False))
    assert alone.status == "solved" and alone.flags == ("CSCTF{EXACT_ONE}",)
    files = {"a.wav": wav, "p.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}
    rep = ros.examine(files, FF, prefixes=("CSCTF",), ledger=False,
                      read=StubOCR(lambda png, scale: "CSCTF{read_by_ocr}" if scale == 1 else ""))
    res = ros.result_of(rep)
    assert set(res.flags) == {"CSCTF{EXACT_ONE}", "CSCTF{read_by_ocr}"}
    assert res.status == "candidate"                                         # two answers: neither is proven the one


def test_flags_are_ranked_by_agreement_across_readings():
    arr = _with_plane(_with_plane(_cover(128, 160), 2, 0, _strokes()), 0, 1, _strokes())
    state = {"n": 0}

    def answer(png, scale):                              # B bit 0 is read first, three sizes; then R bit 1
        state["n"] += 1
        return "CSCTF{read_thrice}" if state["n"] <= 3 else "CSCTF{read_once}" if state["n"] == 4 else ""

    rep = ros.examine({"p.png": _png(arr)}, FF, prefixes=("CSCTF",), read=StubOCR(answer), ledger=False)
    with_flags = [(r.where, [f for f, _ in r.flags]) for r in rep.readings if r.flags]
    assert with_flags == [("R bit 1", ["CSCTF{read_once}"]), ("B bit 0", ["CSCTF{read_thrice}"])]   # report order
    assert list(rep.flags()) == ["CSCTF{read_thrice}", "CSCTF{read_once}"]   # agreement order
    assert ros.result_of(rep).flags == ("CSCTF{read_thrice}", "CSCTF{read_once}")


def test_the_same_bytes_under_two_names_are_read_once():
    data = _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))
    ocr = StubOCR()
    rep = ros.examine({"a/p.png": data, "b/copy.png": data}, FF, read=ocr, ledger=False)
    assert list(rep.files) == ["a/p.png"] and len(rep.readings) == 9 and len(ocr.calls) == 3


def test_a_note_gives_at_most_six_shifts():
    keys = ros.note_keys({"n.png": _lsb_note(b"try 1 then 2 then 3 then 4 then 5 then 6 then 7 then 8")}, SFF)
    assert [k.value for k in keys] == [1, 2, 3, 4, 5, 6] and ros.MAX_NOTE_KEYS == 6


def test_a_paletted_picture_with_transparency_keeps_its_alpha_plane():
    from PIL import Image
    strokes = _strokes()
    im = Image.new("P", (strokes.shape[1], strokes.shape[0]))
    im.putdata(strokes.ravel().tolist())                 # palette entries 0 and 1 ...
    im.putpalette([10, 20, 30, 10, 20, 30])              # ... the same colour, so R, G and B hold nothing
    buf = io.BytesIO()
    im.save(buf, "PNG", transparency=bytes([254, 255]))  # and the drawing is bit 0 of alpha
    arr, labels = ros.image_array(buf.getvalue())
    assert labels == ("R", "G", "B", "A") and np.array_equal(arr[:, :, 3] & 1, strokes)
    rep = ros.examine({"pal.png": buf.getvalue()}, FF, read=StubOCR(), ledger=False)
    assert [r.where for r in rep.readings if r.png is not None] == ["A bit 0"] and len(rep.readings) == 12


def test_a_delivery_too_large_for_the_ledger_is_a_named_note(monkeypatch):
    monkeypatch.setattr(ros, "LEDGER_MAX_BYTES", 1000)
    rep = ros.examine({"a.wav": _wav(_glyph_samples("CSCTF{A1}", 5000, 250, 40))}, FF, prefixes=("CSCTF",), ocr="off")
    assert rep.key_notes == ["evidence-ledger keys not read: the delivery is over 1000 bytes"]
    item = next(i for i in ros.checklist(rep) if i["probe"] == ros.PROBE_KEYS)
    assert item["result"] == "inconclusive" and "a key source was not read to the end" in item["evidence"]


def test_without_crib_decode_the_flags_as_they_stand_are_kept_and_the_decode_is_not_run(monkeypatch):
    def gone():
        raise ImportError("crib_decode (solvers/warmups) is not importable: stub")

    monkeypatch.setattr(ros, "_crib", gone)
    text = "CSCTF{as_it_stands}\n" + base64.b64encode(b"CSCTF{needs_the_decoder}").decode()
    rep = ros.examine({"p.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}, FF, prefixes=("CSCTF",),
                      read=StubOCR(lambda png, scale: text), ledger=False)
    assert list(rep.flags()) == ["CSCTF{as_it_stands}"]
    assert rep.decode == "not run: crib_decode (solvers/warmups) is not importable: stub"
    assert f"keyless decode {rep.decode}" in rep.skipped
    items = {i["probe"]: i for i in ros.checklist(rep)}
    assert items[ros.PROBE_PLANE]["payload"] == "CSCTF{as_it_stands}"
    assert items[ros.PROBE_DECODE]["result"] == "error" and items[ros.PROBE_DECODE]["evidence"] == rep.decode


def test_an_ocr_reading_is_capped_at_max_text():
    rep = ros.examine({"p.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}, FF,
                      read=StubOCR(lambda png, scale: "x" * 5000 + str(scale)), ledger=False)
    r = next(x for x in rep.readings if x.png is not None)
    assert ros.MAX_TEXT == 4000 and r.parts == ["x" * 4000] * 3 and r.text == "x" * 4000


def test_survey_gives_a_png_and_a_bmp_the_render_sweep_row_first(monkeypatch):
    import stego_tools as st
    from PIL import Image
    monkeypatch.setattr(st, "exif", lambda data, name="file": st.Rec(note="sandbox down: stub", tool="exiftool"))
    _no_tesseract(monkeypatch)
    arr = _with_plane(_cover(128, 160), 2, 0, _strokes())
    bmp = io.BytesIO()
    Image.fromarray(arr).save(bmp, "BMP")
    for name, data in (("p.png", _png(arr)), ("p.bmp", bmp.getvalue())):
        rows = st.survey(name, data)
        assert [what for what, _rec in rows] == ["render sweep (spectrogram to Nyquist, bit planes 0-2)", "exiftool"], name
        assert rows[0][1].tool == "render_ocr_sweep" and list(rows[0][1].files) == ["B_bit_0.png"], name


# ---- verification round 1: crib_decode's public entry point ----------------------------------------

def test_crib_decode_readings_within_holds_the_lock_and_restores_the_deadline(monkeypatch):
    import crib_decode as cd
    wrapped = base64.b64encode(b"CSCTF{public_entry}")
    got = cd.readings_within(wrapped, LONG)                                   # the real search, no private state touched
    assert any("CSCTF{public_entry}" in text for text in got)
    assert any("CSCTF{public_entry}" in text for text in ros.keyless_readings(wrapped, LONG))

    def lock_is_free() -> bool:
        seen = []

        def look():
            ok = cd._SOLVE_LOCK.acquire(blocking=False)
            if ok:
                cd._SOLVE_LOCK.release()
            seen.append(ok)

        t = threading.Thread(target=look)
        t.start()
        t.join()
        return seen[0]

    calls = []

    def probe(payload, deadline):
        calls.append({"payload": payload, "deadline": deadline, "free": lock_is_free(),
                      "program": cd.M.DEADLINE[0] if cd.M is not None else deadline})
        if payload == b"boom":
            raise RuntimeError("reader fault")
        return {"text": ("step",)}

    monkeypatch.setattr(cd, "readings", probe)
    before = cd.M.DEADLINE[0] if cd.M is not None else None
    t0 = time.perf_counter()
    assert cd.readings_within(bytearray(b"abc"), 2.0) == {"text": ("step",)}
    seen = calls[0]
    assert seen["payload"] == b"abc" and isinstance(seen["payload"], bytes)
    assert not seen["free"]                                                  # no solve or day read runs beside it
    assert seen["program"] == seen["deadline"] and t0 + 2.0 <= seen["deadline"] <= time.perf_counter() + 2.0
    with pytest.raises(RuntimeError, match="reader fault"):
        cd.readings_within(b"boom", 2.0)
    assert lock_is_free() and (cd.M.DEADLINE[0] if cd.M is not None else None) == before   # also after a fault
    for bad in (0, -1.0, float("inf"), float("nan"), "soon", None):
        with pytest.raises(ValueError, match="seconds must be a positive number"):
            cd.readings_within(b"abc", bad)
    assert len(calls) == 2                                                   # a bad budget never reaches the search


# ---- verification round 2: a reading stopped part way, and a probe that did not see the whole file --

def _stops_after_the_first_size(first: str, fault: Exception):
    """An OCR stand-in that answers the first size of a plane and fails on the second."""
    def answer(png, scale):
        if scale == 1:
            return first
        raise fault
    return answer


def test_a_plane_read_at_fewer_sizes_than_it_was_due_is_not_ruled_out(tmp_path):
    plane = {"p.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}
    cut = ic.OutOfBudget("tesseract --psm 6 stopped after 0.1 s")
    ocr = StubOCR(_stops_after_the_first_size("FOUR PLAIN WORDS HERE", cut))
    rep = ros.examine(plane, FF, prefixes=("CSCTF",), read=ocr, ledger=False, deadline=time.monotonic() + LONG)
    r = next(x for x in rep.readings if x.png is not None)
    assert [scale for _png_bytes, scale in ocr.calls] == [1, 2] and r.scales == (1, 2, 3)
    assert r.state == ros.READ and r.parts == ["FOUR PLAIN WORDS HERE"] and r.text == "FOUR PLAIN WORDS HERE"
    why = "1 of 3 sizes read: out of time: tesseract --psm 6 stopped after 0.1 s"
    assert r.partial == why and rep.out_of_time
    assert rep.skipped == ["OCR: out of time in p.png B bit 0: tesseract --psm 6 stopped after 0.1 s"]
    items = {i["probe"]: i for i in ros.checklist(rep)}
    assert [i["result"] for i in items.values()] == ["inconclusive"] * 3      # none of the three is a no
    assert items[ros.PROBE_PLANE]["evidence"].endswith(f"1 of 9 not read at every size (B bit 0: {why})")
    for probe in (ros.PROBE_DECODE, ros.PROBE_KEYS):
        assert items[probe]["evidence"].endswith(
            f"not ruled out: 1 readings were not made at every size (p.png B bit 0: {why})"), probe
    assert "ruled out ]" not in ros.checklist_text(list(items.values())).split("not covered")[0]
    # the mark survives the saved report, so a checklist made from it later says the same
    saved = ros.Report.from_dict(json.loads(json.dumps(rep.to_dict())))
    assert next(x for x in saved.readings if x.partial).partial == why
    assert ros.checklist(saved) == ros.checklist(rep)
    # and in the hypothesis ledger nothing is settled
    ros.file_checklist("21", ros.checklist(rep), workdir=tmp_path, profile=PROFILE)
    for method in (ros.method_of(ros.PROBE_PLANE, "p.png"), ros.method_of(ros.PROBE_DECODE), ros.method_of(ros.PROBE_KEYS)):
        assert hyp.seen("21", method, tmp_path)["result"] == hyp.INCONCLUSIVE, method
        assert not hyp.should_skip("21", method, tmp_path).skip, method
    # read at all three sizes, the same plane is whole and all three lines are ruled out
    whole = ros.examine(plane, FF, prefixes=("CSCTF",), read=StubOCR(lambda png, scale: "FOUR PLAIN WORDS HERE"),
                        ledger=False, deadline=time.monotonic() + LONG)
    assert all(not x.partial for x in whole.readings)
    assert [i["result"] for i in ros.checklist(whole)] == ["negative"] * 3


def test_a_tesseract_fault_part_way_leaves_the_rendering_waiting_and_a_flag_already_read_stands():
    plane = {"p.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}
    fault = RuntimeError("tesseract exited 1: boom")
    # the first size read nothing, the second failed: no text at all, and still not a no
    rep = ros.examine(plane, FF, prefixes=("CSCTF",), read=StubOCR(_stops_after_the_first_size("", fault)), ledger=False)
    r = next(x for x in rep.readings if x.png is not None)
    assert r.state == ros.READ and r.text == "" and r.partial == "1 of 3 sizes read: tesseract exited 1: boom"
    assert ros.result_of(rep).status == "unsure"                            # the rendering is still waiting for a read
    assert [i["result"] for i in ros.checklist(rep)] == ["inconclusive", "error", "error"]
    # a flag read at the first size is a flag whatever stopped the second
    got = ros.examine(plane, FF, prefixes=("CSCTF",), ledger=False,
                      read=StubOCR(_stops_after_the_first_size("CSCTF{first_size}", fault)))
    item = ros.checklist(got)[0]
    assert item["result"] == "positive" and item["payload"] == "CSCTF{first_size}"
    assert next(x for x in got.readings if x.png is not None).partial


def test_the_engine_catches_what_ocr_text_raises_when_its_time_is_up(monkeypatch):
    """image_carve.ocr_text itself, with no time left: the engine's clock is held (it still has time),
    image_carve's is real (the deadline is past), and the stand-in path is never run."""
    monkeypatch.setattr(ic.shutil, "which", lambda name: "/nonexistent/tesseract")
    monkeypatch.setattr(ros, "time", HeldClock())
    rep = ros.examine({"p.png": _png(_with_plane(_cover(128, 160), 2, 0, _strokes()))}, FF, ledger=False,
                      deadline=time.monotonic() - 1.0)
    r = next(x for x in rep.readings if x.png is not None)
    assert r.state == ros.NOT_READ and r.why == "out of time: no time left for tesseract --psm 6"
    assert rep.skipped == ["OCR: out of time in p.png B bit 0: no time left for tesseract --psm 6"]
    assert rep.out_of_time                                                  # by the note: the held clock is not past


def test_a_glyph_read_of_the_first_minute_only_is_not_ruled_out(tmp_path):
    rng = np.random.default_rng(11)
    late = np.concatenate([rng.normal(0, 0.0005, 61 * RATE), _glyph_samples("CSCTF{LATE}", 9000, 250, 40)])
    rep = ros.examine({"late.wav": _wav(late)}, FF, prefixes=("CSCTF",), read=StubOCR(), ledger=False,
                      deadline=time.monotonic() + LONG)
    assert not rep.flags()                                                  # the writing starts after the 60 s it looks at
    limit = f"only the first 60 s of {late.size / RATE:.1f} s was looked at"
    assert rep.files["late.wav"]["limits"] == {ros.PROBE_GLYPH: limit}
    items = {i["probe"]: i for i in ros.checklist(rep)}
    assert items[ros.PROBE_GLYPH]["result"] == "inconclusive"
    assert items[ros.PROBE_GLYPH]["evidence"].endswith(f"0 read, 1 blank; not ruled out: {limit}")
    assert items[ros.PROBE_SPEC]["result"] == "negative"                    # that probe did read all of it
    assert "[incomplete] spectrogram-5x7  late.wav" in ros.checklist_text(list(items.values()))
    assert ros.checklist(ros.Report.from_dict(json.loads(json.dumps(rep.to_dict())))) == ros.checklist(rep)
    ros.file_checklist("22", ros.checklist(rep), workdir=tmp_path, profile=PROFILE)
    method = ros.method_of(ros.PROBE_GLYPH, "late.wav")
    assert hyp.seen("22", method, tmp_path)["result"] == hyp.INCONCLUSIVE and not hyp.should_skip("22", method, tmp_path).skip
    # the same writing inside the first minute is read, and a short recording with none is ruled out
    early = np.concatenate([rng.normal(0, 0.0005, 2 * RATE), _glyph_samples("CSCTF{LATE}", 9000, 250, 40)])
    got = ros.examine({"early.wav": _wav(early)}, FF, prefixes=("CSCTF",), read=StubOCR(), ledger=False)
    assert list(got.flags()) == ["CSCTF{LATE}"] and "limits" not in got.files["early.wav"]
    quiet = ros.examine({"quiet.wav": _wav(rng.normal(0, 0.05, 3 * RATE))}, FF, read=StubOCR(), ledger=False)
    assert next(i for i in ros.checklist(quiet) if i["probe"] == ros.PROBE_GLYPH)["result"] == "negative"


def test_a_spectrogram_cut_by_top_hz_is_not_ruled_out_above_the_cut():
    noise = {"a.wav": _wav(np.random.default_rng(3).normal(0, 0.05, 3 * RATE))}
    capped = ros.examine(noise, FF, read=StubOCR(), ledger=False, top_hz=8000)
    assert capped.files["a.wav"]["limits"] == {ros.PROBE_SPEC: "8000 to 22050 Hz was not looked at (top_hz)"}
    items = {i["probe"]: i for i in ros.checklist(capped)}
    assert items[ros.PROBE_SPEC]["result"] == "inconclusive"
    assert items[ros.PROBE_SPEC]["evidence"].endswith("not ruled out: 8000 to 22050 Hz was not looked at (top_hz)")
    assert items[ros.PROBE_GLYPH]["result"] == "negative"                   # the glyph reader looks up to Nyquist anyway
    full = ros.examine(noise, FF, read=StubOCR(), ledger=False)
    assert "limits" not in full.files["a.wav"]
    assert next(i for i in ros.checklist(full) if i["probe"] == ros.PROBE_SPEC)["result"] == "negative"
    at_nyquist = ros.examine(noise, FF, read=StubOCR(), ledger=False, top_hz=30000)      # a cut above Nyquist cuts nothing
    assert next(i for i in ros.checklist(at_nyquist) if i["probe"] == ros.PROBE_SPEC)["result"] == "negative"


def test_an_evidence_ledger_read_that_passes_the_deadline_leaves_the_keys_open(monkeypatch):
    clock = HeldClock()
    monkeypatch.setattr(ros, "time", clock)
    started = []

    def slow_ledger(files, deadline=None):
        started.append(sorted(files))
        clock.back = 0.0                              # the read of the delivery took the rest of the budget
        return []

    monkeypatch.setattr(ros, "ledger_keys", slow_ledger)
    rep = ros.examine({"a.wav": _wav(_glyph_samples("PUMPKINLANTERN", 9000, 250, 40))}, FF, prefixes=("CSCTF",),
                      ocr="off", deadline=time.monotonic() - 1.0)
    monkeypatch.undo()
    assert started == [["a.wav"]]                                           # it was started in time, and overran
    assert [r.text for r in rep.readings if r.exact] == ["PUMPKINLANTERN"]
    assert rep.key_notes == ["evidence-ledger keys: out of time while the delivery was read, so some may be missing"]
    assert rep.out_of_time
    item = next(i for i in ros.checklist(rep) if i["probe"] == ros.PROBE_KEYS)
    assert item["result"] == "inconclusive" and "a key source was not read to the end" in item["evidence"]
    assert "evidence-ledger keys: out of time while the delivery was read" in item["evidence"]
    # the same ledger read inside the budget: no note, and the keys line is not held open by it
    monkeypatch.setattr(ros, "ledger_keys", lambda files, deadline=None: [])
    in_time = ros.examine({"a.wav": _wav(_glyph_samples("PUMPKINLANTERN", 9000, 250, 40))}, FF, prefixes=("CSCTF",),
                          read=StubOCR(), deadline=time.monotonic() + LONG)
    assert in_time.key_notes == [] and not in_time.out_of_time
    assert next(i for i in ros.checklist(in_time) if i["probe"] == ros.PROBE_KEYS)["result"] == "negative"


def test_cli_seconds_decides_whether_a_report_the_clock_cut_is_reused(tmp_path, capsys):
    d = _glyph_challenge(tmp_path, flag="SPOOKY{CLI_FLAG}", cid="57")
    report = ros.default_out(d) / "report.json"

    def source(*more):
        assert _cli("--event", "spooky", "--workdir", str(tmp_path / "work"), "checklist", str(d), "--ocr", "off",
                    "--json", *more) == 0
        return json.loads(capsys.readouterr().out)["source"]

    cut = "fresh sweep: the saved report ran out of time, on a smaller budget than this run has"
    assert source("--seconds", "-1") == "fresh sweep"                       # a budget spent before it began
    saved = json.loads(report.read_text())
    assert saved["out_of_time"] is True and saved["seconds"] == -1.0
    assert source("--seconds", "-1") == "saved report"                      # no more time than it had: the same answer
    assert source("--seconds", str(LONG)) == cut                            # more time: run again
    assert json.loads(report.read_text())["out_of_time"] is False
    assert source("--seconds", "-1") == "saved report"                      # a run that was not cut answers any budget
    # a report cut on a budget above the engine's default: --seconds, not the default, is what is compared
    saved = json.loads(report.read_text())
    saved.update(out_of_time=True, seconds=100.0)
    report.write_text(json.dumps(saved))
    assert source("--seconds", "50") == "saved report"
    assert source() == "saved report"                                       # the default (40 s) is under 100 s too
    assert source("--seconds", "200") == cut


def test_a_text_file_that_begins_like_a_picture_does_not_stop_the_report_being_reused(tmp_path):
    d = _glyph_challenge(tmp_path)
    (d / "files" / "readme.txt").write_bytes(b"BM stands for bitmap, but this file is only words about one.")
    (d / "files" / "kinds.txt").write_bytes(b"P5 and P6 are the binary PGM and PPM kinds.")
    (d / "files" / "torn.png").write_bytes(ic.PNG_SIG + b"not a picture at all")
    rep = ros.sweep(d, PROFILE, seconds=LONG, ocr="off", ledger="off")
    assert sorted(rep.files) == ["files/tones.wav", "files/torn.png"]       # the two notes are not pictures
    files = ic.challenge_files(d)
    assert {n: ros.swept(data) for n, data in files.items()} == {
        "files/kinds.txt": False, "files/readme.txt": False, "files/tones.wav": True, "files/torn.png": True}
    assert ros.load_report(ros.default_out(d), files) is not None           # so the saved report is the answer
    want = ros.run_options(FF, ocr="off", prefixes=("CSCTF",), ledger=False)
    assert ros.load_report(ros.default_out(d), files, want, seconds=LONG) is not None
    (d / "files" / "torn.png").write_bytes(ic.PNG_SIG + b"torn another way")
    assert ros.load_report(ros.default_out(d), ic.challenge_files(d)) is None    # a damaged picture still counts
    from PIL import Image
    buf = io.BytesIO()
    Image.fromarray(_cover(16, 16)).save(buf, "JPEG")
    assert not ros.swept(buf.getvalue()) and ros.swept(_png(_cover(16, 16))) and not ros.swept(b"plain words")
