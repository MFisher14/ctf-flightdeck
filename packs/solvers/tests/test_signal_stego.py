"""Deterministic positive and corrupt/decline tests for signal_stego_depth."""
from __future__ import annotations

import io
import sys
import wave
from pathlib import Path

import numpy as np
import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

import signal_stego_depth as sig  # noqa: E402


RATE = 8000


def _bits(data: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def _tone(frequency: float, samples: int, rate: int = RATE, phase: float = 0.0, amp: float = 0.72):
    t = np.arange(samples, dtype=np.float64) / rate
    return amp * np.sin(2 * np.pi * frequency * t + phase)


def _wav(samples: np.ndarray, rate: int = RATE) -> bytes:
    pcm = np.clip(np.rint(samples * 32767), -32768, 32767).astype("<i2").tobytes()
    out = io.BytesIO()
    with wave.open(out, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(rate)
        wf.writeframes(pcm)
    return out.getvalue()


def _fsk(bits: list[int], rate: int = RATE, baud: int = 100) -> np.ndarray:
    size = rate // baud
    return np.concatenate([_tone(2200 if bit else 1200, size, rate) for bit in bits])


def test_fsk_checked_and_corrupt_declines():
    payload = b"two-tone-fsk"
    bits = _bits(sig.checked_frame(payload))
    assert sig.decode_fsk(_wav(_fsk(bits)), baud=100) == payload
    bad = bits.copy()
    bad[-3] ^= 1
    assert sig.decode_fsk(_wav(_fsk(bad)), baud=100) is None
    assert sig.decode_fsk(b"not a wav", baud=100) is None


def test_real_fsk_ask_psk_candidates_are_labeled_not_proven():
    flag = b"CSCTF{RAW_MODEMS}"
    bits = _bits(flag)
    for candidates in (
        sig.fsk_candidates(_wav(_fsk(bits))),
        sig.ask_candidates(_ask(bits), sample_rate=RATE),
        sig.psk_candidates(_dbpsk(bits), sample_rate=RATE),
    ):
        match = next(candidate for candidate in candidates if candidate.payload == flag)
        assert not match.proven
        assert "flag shape" in match.check
        assert 0 < match.confidence <= 1
    # The old APIs retain their proven-only contract.
    assert sig.decode_fsk(_wav(_fsk(bits))) is None
    assert sig.decode_ask(_ask(bits), sample_rate=RATE) is None
    assert sig.decode_psk(_dbpsk(bits), sample_rate=RATE) is None
    assert sig.fsk_candidates(np.zeros(RATE), sample_rate=RATE) == []


def _ask(bits: list[int], rate: int = RATE, baud: int = 100) -> np.ndarray:
    size = rate // baud
    return np.concatenate([_tone(1800, size, rate) if bit else np.zeros(size) for bit in bits])


def test_ask_checked_and_corrupt_declines():
    payload = b"ook payload"
    bits = _bits(sig.checked_frame(payload))
    assert sig.decode_ask(_ask(bits), sample_rate=RATE) == payload
    bad = bits.copy()
    bad[-1] ^= 1
    assert sig.decode_ask(_ask(bad), sample_rate=RATE) is None
    assert sig.decode_ask(np.zeros(5000), sample_rate=RATE) is None


def _dbpsk(bits: list[int], rate: int = RATE, baud: int = 100,
           carrier: float = 1800.0) -> np.ndarray:
    size, phase, index = int(round(rate / baud)), 0.0, 0

    def continuous_tone(data_phase: float):
        nonlocal index
        n = np.arange(size, dtype=np.float64) + index
        index += size
        return 0.72 * np.sin(2 * np.pi * carrier * n / rate + data_phase)

    chunks = [continuous_tone(phase)]  # differential reference
    for bit in bits:
        if bit:
            phase += np.pi
        chunks.append(continuous_tone(phase))
    return np.concatenate(chunks)


def test_psk_checked_and_corrupt_declines():
    payload = b"differential-bpsk"
    bits = _bits(sig.checked_frame(payload))
    assert sig.decode_psk(_wav(_dbpsk(bits))) == payload
    bad = bits.copy()
    bad[-9] ^= 1
    assert sig.decode_psk(_wav(_dbpsk(bad))) is None
    assert sig.decode_psk(np.zeros(9000), sample_rate=RATE) is None
    # A non-integral carrier-cycles-per-symbol ratio exercises phase derotation.
    assert sig.decode_psk(_dbpsk(bits, baud=125, carrier=1730), sample_rate=RATE,
                          baud=125, carrier_hz=1730) == payload


def _dtmf(frame: bytes, corrupt_symbol: int | None = None) -> np.ndarray:
    nibble_symbols = "0123456789ABCD*#"
    symbols = [nibble_symbols[value] for byte in frame for value in (byte >> 4, byte & 15)]
    if corrupt_symbol is not None:
        current = nibble_symbols.index(symbols[corrupt_symbol])
        symbols[corrupt_symbol] = nibble_symbols[(current + 1) & 15]
    chunks = []
    for symbol in symbols:
        row, col = next((r, c) for r, line in enumerate(sig.DTMF_KEYS) for c, key in enumerate(line)
                        if key == symbol)
        n = int(RATE * 0.070)
        chunks.append((_tone(sig.DTMF_ROWS[row], n) + _tone(sig.DTMF_COLS[col], n)) * 0.48)
        chunks.append(np.zeros(int(RATE * 0.020)))
    return np.concatenate(chunks)


def test_dtmf_nibble_checked_and_corrupt_declines():
    payload = b"DTMF-16"
    frame = sig.checked_frame(payload)
    assert sig.decode_dtmf(_wav(_dtmf(frame))) == payload
    assert sig.decode_dtmf(_wav(_dtmf(frame, corrupt_symbol=len(frame) * 2 - 1))) is None
    assert sig.decode_dtmf(_wav(np.zeros(RATE))) is None


def _ordinary_dtmf(symbols: str, *, noisy_gap: bool = False) -> np.ndarray:
    chunks = []
    for index, symbol in enumerate(symbols):
        row, col = next((r, c) for r, line in enumerate(sig.DTMF_KEYS) for c, key in enumerate(line)
                        if key == symbol)
        n = int(RATE * 0.070)
        chunks.append((_tone(sig.DTMF_ROWS[row], n) + _tone(sig.DTMF_COLS[col], n)) * 0.48)
        gap = np.zeros(int(RATE * 0.020))
        if noisy_gap and index == 1:
            gap = _tone(900, gap.size)
        chunks.append(gap)
    return np.concatenate(chunks)


def test_ordinary_dtmf_symbols_are_checked_candidates():
    candidates = sig.dtmf_candidates(_ordinary_dtmf("8675309"), sample_rate=RATE)
    assert len(candidates) == 1
    assert candidates[0].payload == b"8675309" and not candidates[0].proven
    assert "quiet gaps" in candidates[0].check
    assert sig.dtmf_candidates(_ordinary_dtmf("8675309", noisy_gap=True), sample_rate=RATE) == []
    assert sig.dtmf_candidates(_ordinary_dtmf("12"), sample_rate=RATE) == []


_MORSE_INV = {value: key for key, value in sig.MORSE.items()}


def _morse(text: str, *, bad_first: bool = False, unit_ms: int = 50) -> np.ndarray:
    unit = RATE * unit_ms // 1000
    chunks = []
    first = True
    for ci, char in enumerate(text):
        code = _MORSE_INV[char]
        for si, mark in enumerate(code):
            length = 1 if mark == "." else 3
            if bad_first and first:
                length = 5
            first = False
            chunks.append(_tone(700, length * unit))
            if si + 1 < len(code):
                chunks.append(np.zeros(unit))
        if ci + 1 < len(text):
            chunks.append(np.zeros(3 * unit))
    return np.concatenate(chunks)


def test_morse_cadence_checked_and_corrupt_declines():
    assert sig.decode_morse_tone(_wav(_morse("SOS")), unit_ms=50) == b"SOS"
    assert sig.decode_morse_tone(_wav(_morse("SOS", bad_first=True)), unit_ms=50) is None
    assert sig.decode_morse_tone(_wav(np.zeros(RATE))) is None


def _spectrogram(text: str, *, flip: tuple[int, int, int] | None = None) -> np.ndarray:
    column = int(RATE * 0.050)
    chunks = []
    for gi, char in enumerate(text):
        pattern = [list(row) for row in sig.FONT_5X7[char]]
        if flip is not None and flip[0] == gi:
            row, col = flip[1], flip[2]
            pattern[row][col] = "0" if pattern[row][col] == "1" else "1"
        for col in range(5):
            active = [row for row in range(7) if pattern[row][col] == "1"]
            if active:
                mixed = sum((_tone(500 + row * 200, column, amp=0.7 / len(active) ** 0.5)
                             for row in active), np.zeros(column))
                chunks.append(mixed)
            else:
                chunks.append(np.zeros(column))
        chunks.append(np.zeros(column))
    return np.concatenate(chunks)


def test_spectrogram_exact_glyphs_and_corrupt_decline():
    text = "CSCTF{A1}"
    audio = _spectrogram(text)
    assert sig.decode_spectrogram_text(audio, sample_rate=RATE, column_ms=50,
                                       row_step_hz=200) == text.encode()
    corrupt = _spectrogram(text, flip=(1, 0, 0))
    assert sig.decode_spectrogram_text(corrupt, sample_rate=RATE, column_ms=50,
                                       row_step_hz=200) is None
    assert sig.decode_spectrogram_text(np.zeros(RATE), sample_rate=RATE) is None


def _sstv_martin_line(*, corrupt_parity: bool = False, rate: int = 48000,
                      vis: int = 44, scan_ms: float = 146.432) -> np.ndarray:
    def ms_tone(frequency: float, duration: float):
        return _tone(frequency, int(round(rate * duration / 1000)), rate)

    chunks = [ms_tone(1900, 300), ms_tone(1200, 10), ms_tone(1900, 300), ms_tone(1200, 30)]
    bits = [(vis >> i) & 1 for i in range(7)]
    parity = sum(bits) & 1
    bits.append(parity ^ int(corrupt_parity))
    chunks.extend(ms_tone(1100 if bit else 1300, 30) for bit in bits)
    chunks.append(ms_tone(1200, 30))
    # One Martin M1 line: sync, porch, G, separator, B, separator, R, separator.
    chunks.extend([
        ms_tone(1200, 4.862), ms_tone(1500, 0.572), ms_tone(1900, scan_ms),
        ms_tone(1500, 0.572), ms_tone(1700, scan_ms), ms_tone(1500, 0.572),
        ms_tone(2100, scan_ms), ms_tone(1500, 0.572),
    ])
    return np.concatenate(chunks)


def test_sstv_vis_parity_and_corrupt_decline():
    decoded = sig.decode_sstv_martin_m1(_sstv_martin_line(), sample_rate=48000)
    assert decoded is not None and decoded.startswith(b"P6\n320 1\n255\n")
    assert len(decoded) == len(b"P6\n320 1\n255\n") + 320 * 3
    assert sig.decode_sstv_martin_m1(_sstv_martin_line(corrupt_parity=True),
                                     sample_rate=48000) is None
    assert sig.decode_sstv_martin_m1(np.zeros(48000), sample_rate=48000) is None


def test_sstv_martin_m2_and_vis_inspection():
    audio = _sstv_martin_line(vis=40, scan_ms=73.216)
    meta = sig.detect_sstv_vis(audio, sample_rate=48000)
    assert meta is not None and meta["vis"] == 40 and meta["mode"] == "Martin M2"
    decoded = sig.decode_sstv_martin_m2(audio, sample_rate=48000)
    assert decoded is not None and decoded.startswith(b"P6\n320 1\n255\n")
    assert sig.decode_sstv_martin(audio, sample_rate=48000) == decoded
    assert sig.decode_sstv_martin_m1(audio, sample_rate=48000) is None
    assert sig.detect_sstv_vis(_sstv_martin_line(corrupt_parity=True), sample_rate=48000) is None


def test_ggwave_library_protocol_and_corrupt_decline():
    ggwave = pytest.importorskip("ggwave")
    ggwave.disableLog()
    payload = b"ggwave-checked"
    waveform = ggwave.encode(payload, protocolId=1, volume=15)
    assert sig.decode_ggwave(waveform, raw_float32=True) == payload
    assert sig.decode_ggwave(bytes(len(waveform)), raw_float32=True) is None
    assert sig.decode_ggwave(waveform[:1000], raw_float32=True) is None


def test_raw_pcm_reader_is_bounded_and_explicit():
    payload = b"raw-pcm"
    samples = _fsk(_bits(sig.checked_frame(payload)))
    pcm = np.clip(np.rint(samples * 32767), -32768, 32767).astype("<i2").tobytes()
    assert sig.decode_fsk(pcm, sample_rate=RATE) == payload
    assert sig.decode_fsk(pcm) is None
    assert sig.read_audio(np.array([0.0, np.nan]), sample_rate=RATE) is None
    assert sig.read_audio(np.zeros(10), sample_rate=float("nan")) is None
    assert sig.fsk_candidates(np.zeros(100), sample_rate=RATE, baud=0) == []
