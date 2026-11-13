#!/usr/bin/env python3
"""Synthetic regression for solvers/toolkits/sound_data.py (data-over-sound decoder hub).

All fixtures are built IN-TEST (no sample files on disk):

  * ggwave  -- if the `ggwave` codec can encode, round-trip "CSCTF{...}" through a WAV and assert
               decode_ggwave recovers it. When ggwave is NOT importable, assert the recipe-fallback
               path instead (available False, the recipe string present).
  * DTMF    -- synthesise a two-tone "911" recording and assert decode_dtmf routes to carve_stego
               and reads the keys.
  * tones   -- synthesise a CyberSonics linear tone ladder and assert decode_tones recovers the flag.
  * recipes -- assert the modem/Morse recipe card names multimon-ng + minimodem (we do not reimplement
               a modem) and the ggwave fallback path is always available even without the codec.

Standalone:

    CTF_WORKDIR=/tmp/ctfdur .venv/bin/python tests/test_sound_data.py   -> prints 'ok', exit 0
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
import sound_data as sd                     # noqa: E402

FLAG = "CSCTF{s0und_d4ta_hub}"
SR = 16000


def _write_wav(path, samples, sr=SR):
    sf.write(str(path), np.asarray(samples, dtype=np.float32), sr, subtype="PCM_16")


# ---- (a) ggwave: round-trip if we can encode, else the recipe fallback -------------------------

def test_ggwave_roundtrip_or_recipe():
    try:
        import ggwave
    except Exception:
        ggwave = None

    with tempfile.TemporaryDirectory() as d:
        wav = Path(d) / "gg.wav"
        if ggwave is not None:
            try:
                ggwave.disableLog()
            except Exception:
                pass
            buf = ggwave.encode(FLAG, protocolId=1, volume=20)
            arr = np.frombuffer(buf, dtype=np.int16).astype(np.float32) / 32768.0
            _write_wav(wav, arr, sr=sd.GGWAVE_RATE)
            res = sd.decode_ggwave(wav)
            assert res["available"] is True, res
            assert res["payload"] == FLAG, f"ggwave payload mismatch: {res['payload']!r}"
            assert sd.find_flags(res) == [FLAG], sd.find_flags(res)
        else:
            # no codec: a WAV still loads, but decode_ggwave must report the recipe, not crash.
            _write_wav(wav, np.zeros(SR // 2, dtype=np.float32))
            res = sd.decode_ggwave(wav)
            assert res["available"] is False, res
            assert "ggwave" in res["recipe"] and "sampleRateInp" in res["recipe"], res["recipe"]


def test_ggwave_recipe_fallback_when_absent():
    """Force ggwave to look un-importable and assert the recipe path (covers the fallback even when
    the codec IS installed)."""
    saved = sys.modules.get("ggwave", "__missing__")
    sys.modules["ggwave"] = None            # import ggwave -> ImportError
    try:
        with tempfile.TemporaryDirectory() as d:
            wav = Path(d) / "silence.wav"
            _write_wav(wav, np.zeros(SR // 2, dtype=np.float32))
            res = sd.decode_ggwave(wav)
        assert res["available"] is False, res
        assert res["payload"] is None
        assert "ggwave" in res["recipe"].lower()
    finally:
        if saved == "__missing__":
            sys.modules.pop("ggwave", None)
        else:
            sys.modules["ggwave"] = saved


# ---- (b) DTMF: a real two-tone recording routes to carve_stego ---------------------------------

def _dtmf_tone(f_lo, f_hi, ms, sr=SR):
    n = int(sr * ms / 1000.0)
    t = np.arange(n) / sr
    return 0.5 * (np.sin(2 * np.pi * f_lo * t) + np.sin(2 * np.pi * f_hi * t))


def test_dtmf_real_recording():
    keys = {"9": (852, 1477), "1": (697, 1209)}
    sig = [np.zeros(int(SR * 0.05))]
    for k in "911":
        lo, hi = keys[k]
        sig.append(_dtmf_tone(lo, hi, 120))
        sig.append(np.zeros(int(SR * 0.08)))
    with tempfile.TemporaryDirectory() as d:
        wav = Path(d) / "dtmf.wav"
        _write_wav(wav, np.concatenate(sig))
        res = sd.decode_dtmf(wav)
    assert res["keys"] == "911", f"DTMF keys mismatch: {res['keys']!r}"
    assert res["sure"] is True, res


# ---- (c) CyberSonics tone ladder routes to audio_tones -----------------------------------------

def test_tone_ladder():
    base, step = 200.0, 20.0
    tone_ms, gap_ms = 220, 40
    chunks = [np.zeros(int(SR * gap_ms / 1000.0))]
    for ch in FLAG:
        f = base + step * ord(ch)
        n = int(SR * tone_ms / 1000.0)
        t = np.arange(n) / SR
        chunks.append(0.6 * np.sin(2 * np.pi * f * t))
        chunks.append(np.zeros(int(SR * gap_ms / 1000.0)))
    with tempfile.TemporaryDirectory() as d:
        wav = Path(d) / "tones.wav"
        _write_wav(wav, np.concatenate(chunks))
        res = sd.decode_tones(wav, mode="linear", base=base, step=step)
    text = res["candidates"][0][1]
    assert text == FLAG, f"tone-ladder decode mismatch: {text!r} != {FLAG!r}"
    assert sd.find_flags(res) == [FLAG], sd.find_flags(res)


# ---- (d) recipe card names the modem tools (we do NOT reimplement a modem) ----------------------

def test_recipes_point_at_sandbox_tools():
    card = sd.recipes()
    for needle in ("multimon-ng", "minimodem", "AFSK1200", "MORSE_CW", "tools/sandbox.py"):
        assert needle in card, f"recipe card missing {needle!r}"


# ---- load_wav handles a plain PCM WAV with no soundfile dependency path -------------------------

def test_load_wav_mono_int16():
    with tempfile.TemporaryDirectory() as d:
        wav = Path(d) / "x.wav"
        sig = 0.3 * np.sin(2 * np.pi * 440 * np.arange(SR) / SR)
        _write_wav(wav, sig)
        wd = sd.load_wav(wav)
    assert wd.samplerate == SR
    assert wd.nchannels == 1
    assert len(wd.int16()) == wd.nframes == SR


def main():
    os.environ.setdefault("CTF_WORKDIR", "/tmp/ctfdur")
    test_ggwave_roundtrip_or_recipe()
    test_ggwave_recipe_fallback_when_absent()
    test_dtmf_real_recording()
    test_tone_ladder()
    test_recipes_point_at_sandbox_tools()
    test_load_wav_mono_int16()
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
