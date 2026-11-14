#!/usr/bin/env python3
"""Fuller offline RF acquisition chains for supplied IQ/WAV/measurement artifacts.

The earlier :mod:`sdr_protocols` module provides protocol primitives.  This module adds bounded
clock/tone acquisition, LoRa diagonal coding helpers, POCSAG/AIS configuration search, GPS L1 C/A
acquisition, and GNSS measurement/spoofing evidence analysis.  It never opens a radio, sound device,
network endpoint, or subprocess, and it never transmits.
For an unaligned IQ capture (LoRa, POCSAG, GFSK, P25, TETRA, SSTV from IQ) use iq_demod.py instead.
"""
from __future__ import annotations

import argparse
import cmath
import collections
import csv
import io
import json
import math
import statistics
from pathlib import Path
from typing import Any, Iterable, Sequence

import sdr_protocols as sdr


MAX_SAMPLES = 2_000_000
MAX_BITS = 8_000_000
MAX_RECORDS = 200_000
MAX_ACQUISITION_WORK = 32_000_000
GPS_CA_RATE = 1_023_000.0
GPS_L1_HZ = 1_575_420_000.0
SPEED_OF_LIGHT = 299_792_458.0


class RFDemodError(ValueError):
    """A saved RF artifact or requested acquisition exceeds a safe deterministic bound."""


def _finite(value: float, what: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise RFDemodError(f"invalid {what}") from exc
    if not math.isfinite(result):
        raise RFDemodError(f"non-finite {what}")
    return result


def _complex_samples(values: Sequence[complex]) -> list[complex]:
    if len(values) > MAX_SAMPLES:
        raise RFDemodError("sample cap exceeded")
    out = [complex(value) for value in values]
    if any(not math.isfinite(value.real) or not math.isfinite(value.imag) for value in out):
        raise RFDemodError("non-finite IQ sample")
    return out


def remove_dc(iq: Sequence[complex]) -> list[complex]:
    """Subtract the exact finite-capture complex mean."""
    values = _complex_samples(iq)
    if not values:
        return []
    mean = sum(values) / len(values)
    return [value - mean for value in values]


def gaussian_kernel(samples_per_symbol: int, bt: float = 0.5, *, span: int = 3) -> list[float]:
    if not 2 <= samples_per_symbol <= 1_000_000 or not 0.05 <= bt <= 2.0 or not 1 <= span <= 8:
        raise RFDemodError("invalid Gaussian filter configuration")
    # Gaussian impulse response whose -3 dB bandwidth is approximately BT/T.
    sigma = math.sqrt(math.log(2.0)) * samples_per_symbol / (2.0 * math.pi * bt)
    radius = min(span * samples_per_symbol // 2, 65_535)
    values = [math.exp(-0.5 * (position / sigma) ** 2) for position in range(-radius, radius + 1)]
    total = sum(values)
    return [value / total for value in values]


def fir_filter(values: Sequence[float], taps: Sequence[float]) -> list[float]:
    if len(values) > MAX_SAMPLES or not taps or len(taps) > 131_071:
        raise RFDemodError("invalid bounded FIR input")
    source = [_finite(value, "FIR sample") for value in values]
    kernel = [_finite(value, "FIR tap") for value in taps]
    if len(source) * len(kernel) > MAX_ACQUISITION_WORK:
        raise RFDemodError("FIR work cap exceeded")
    center = len(kernel) // 2
    output = []
    for index in range(len(source)):
        left = max(0, index - center)
        right = min(len(source), index + len(kernel) - center)
        output.append(sum(source[position] * kernel[position - index + center] for position in range(left, right)))
    return output


def _symbol_means(values: Sequence[float], samples_per_symbol: int, offset: int) -> list[float]:
    return [sum(values[start:start + samples_per_symbol]) / samples_per_symbol
            for start in range(offset, len(values) - samples_per_symbol + 1, samples_per_symbol)]


def _two_cluster(values: Sequence[float]) -> tuple[float, float, float, float]:
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    ordered = sorted(values)
    # Extremal initialization still finds both occupied tones when a packet is very unbalanced
    # (AIS idle fields and pager payloads can easily be >75% one symbol).
    lower, upper = ordered[0], ordered[-1]
    for _ in range(12):
        threshold = (lower + upper) / 2.0
        lows = [value for value in values if value < threshold]
        highs = [value for value in values if value >= threshold]
        if not lows or not highs:
            break
        new_lower, new_upper = sum(lows) / len(lows), sum(highs) / len(highs)
        if abs(new_lower - lower) + abs(new_upper - upper) < 1e-12:
            lower, upper = new_lower, new_upper
            break
        lower, upper = new_lower, new_upper
    threshold = (lower + upper) / 2.0
    threshold = (lower + upper) / 2.0
    residuals = [(value - (lower if value < threshold else upper)) ** 2 for value in values]
    within = math.sqrt(sum(residuals) / len(residuals))
    eye = abs(upper - lower) / (within + 1e-15)
    return lower, upper, threshold, eye


def gfsk_demodulate(
    iq: Sequence[complex], sample_rate: float, baud: float, *, bt: float = 0.5,
    timing_offset: int | None = None, invert: bool = False, matched_filter: bool = True,
) -> dict[str, Any]:
    """Discriminate GFSK/FSK and recover symbol timing by maximum two-cluster eye opening."""
    values = _complex_samples(iq)
    rate, symbol_rate = _finite(sample_rate, "sample rate"), _finite(baud, "baud")
    if rate <= 0 or symbol_rate <= 0:
        raise RFDemodError("sample rate and baud must be positive")
    try:
        ratio = rate / symbol_rate
    except OverflowError as exc:
        raise RFDemodError("sample rate to baud ratio overflows") from exc
    if not math.isfinite(ratio):
        raise RFDemodError("sample rate to baud ratio is not finite")
    samples_per_symbol = int(round(ratio))
    if not 2 <= samples_per_symbol <= 1_000_000 or abs(ratio - samples_per_symbol) > 0.02:
        raise RFDemodError("capture must have near-integral samples per symbol")
    discriminator = sdr.quadrature_discriminator(values)
    if matched_filter and discriminator:
        taps = gaussian_kernel(samples_per_symbol, bt, span=1)
        discriminator = fir_filter(discriminator, taps)
    offsets = range(samples_per_symbol) if timing_offset is None else (timing_offset,)
    best: tuple[float, int, list[float], float, float, float] | None = None
    for offset in offsets:
        if not 0 <= offset < samples_per_symbol:
            raise RFDemodError("timing offset outside one symbol")
        symbols = _symbol_means(discriminator, samples_per_symbol, offset)
        if not symbols:
            continue
        low, high, center, eye = _two_cluster(symbols)
        # Prefer offsets with more complete symbols only after eye quality.
        score = eye + min(len(symbols), 1024) * 1e-9
        if best is None or score > best[0]:
            best = score, offset, symbols, low, high, center
    if best is None:
        return {"bits": "", "symbols": [], "samples_per_symbol": samples_per_symbol,
                "timing_offset": 0, "decision_center_radians": 0.0, "eye_opening": 0.0}
    _, offset, symbols, low, high, center = best
    bits = "".join("1" if (value >= center) ^ invert else "0" for value in symbols)
    eye = _two_cluster(symbols)[3]
    return {
        "bits": bits, "symbols": symbols, "samples_per_symbol": samples_per_symbol,
        "timing_offset": offset, "decision_center_radians": center,
        "low_tone_radians": low, "high_tone_radians": high,
        "frequency_deviation_hz": abs(high - low) * rate / (4.0 * math.pi),
        "eye_opening": eye, "inverted": invert,
    }


def level_demodulate(
    samples: Sequence[float], sample_rate: float, baud: float, *,
    timing_offset: int | None = None, invert: bool = False,
) -> dict[str, Any]:
    """Recover binary symbols from a saved real discriminator/audio stream."""
    if len(samples) > MAX_SAMPLES:
        raise RFDemodError("audio sample cap exceeded")
    values = [_finite(value, "audio sample") for value in samples]
    rate, symbol_rate = _finite(sample_rate, "sample rate"), _finite(baud, "baud")
    if rate <= 0 or symbol_rate <= 0:
        raise RFDemodError("sample rate and baud must be positive")
    try:
        ratio = rate / symbol_rate
    except OverflowError as exc:
        raise RFDemodError("sample rate to baud ratio overflows") from exc
    if not math.isfinite(ratio):
        raise RFDemodError("sample rate to baud ratio is not finite")
    samples_per_symbol = int(round(ratio))
    if not 2 <= samples_per_symbol <= 1_000_000 or abs(ratio - samples_per_symbol) > 0.02:
        raise RFDemodError("audio capture must have near-integral samples per symbol")
    offsets = range(samples_per_symbol) if timing_offset is None else (timing_offset,)
    best = None
    for offset in offsets:
        if not 0 <= offset < samples_per_symbol:
            raise RFDemodError("timing offset outside one symbol")
        symbols = _symbol_means(values, samples_per_symbol, offset)
        if not symbols:
            continue
        low, high, center, eye = _two_cluster(symbols)
        candidate = eye, len(symbols), -offset
        if best is None or candidate > best[0]:
            best = candidate, offset, symbols, low, high, center
    if best is None:
        return {"bits": "", "symbols": [], "samples_per_symbol": samples_per_symbol,
                "timing_offset": 0, "decision_center": 0.0, "eye_opening": 0.0}
    _, offset, symbols, low, high, center = best
    return {"bits": "".join("1" if (value >= center) ^ invert else "0" for value in symbols),
            "symbols": symbols, "samples_per_symbol": samples_per_symbol, "timing_offset": offset,
            "decision_center": center, "low_level": low, "high_level": high,
            "eye_opening": _two_cluster(symbols)[3], "inverted": invert}


def load_stereo_iq_wav(data: bytes, *, i_channel: int = 0, q_channel: int = 1) -> tuple[list[complex], int]:
    """Load two channels of a supplied PCM WAV as complex baseband."""
    try:
        i_values, i_rate = sdr.load_wav(data, channel=i_channel)
        q_values, q_rate = sdr.load_wav(data, channel=q_channel)
    except sdr.SDRDecodeError as exc:
        raise RFDemodError(str(exc)) from exc
    if i_rate != q_rate or len(i_values) != len(q_values) or i_channel == q_channel:
        raise RFDemodError("WAV I/Q channels are inconsistent")
    return [complex(left, right) for left, right in zip(i_values, q_values)], i_rate


def pn9(data: bytes, *, seed: int = 0x1FF) -> bytes:
    """Apply the self-inverse x^9+x^5+1 whitening sequence, LSB first per octet."""
    if not isinstance(data, bytes) or len(data) > MAX_BITS // 8 or not 0 < seed < 512:
        raise RFDemodError("invalid PN9 input or seed")
    state, output = seed, bytearray()
    for byte in data:
        value = 0
        for bit in range(8):
            whitening = state & 1
            value |= (((byte >> bit) & 1) ^ whitening) << bit
            feedback = ((state >> 0) ^ (state >> 5)) & 1   # x^9 + x^5 + 1 (CC1101/TI PN9)
            state = (state >> 1) | (feedback << 8)
        output.append(value)
    return bytes(output)


# ------------------------------------------------------------------ LoRa acquisition and coding

def _lora_chirp(chips: int, *, down: bool = False) -> list[complex]:
    base = [cmath.exp(2j * math.pi * ((index * index) / (2.0 * chips) - index / 2.0)) for index in range(chips)]
    return [value.conjugate() for value in base] if down else base


def _collapse_chips(block: Sequence[complex], chips: int, samples_per_chip: int) -> list[complex]:
    return [sum(block[index * samples_per_chip:(index + 1) * samples_per_chip]) / samples_per_chip for index in range(chips)]


def lora_symbol_bins(
    iq: Sequence[complex], spreading_factor: int, *, samples_per_chip: int = 1,
    offset: int = 0, downchirp: bool = False,
) -> list[int]:
    """Dechirp oversampled aligned symbols and return maximum FFT bins."""
    values = _complex_samples(iq)
    if not 5 <= spreading_factor <= 12 or not 1 <= samples_per_chip <= 64:
        raise RFDemodError("invalid LoRa spreading factor or oversampling")
    chips = 1 << spreading_factor
    width = chips * samples_per_chip
    if not 0 <= offset < width:
        raise RFDemodError("LoRa offset outside one symbol")
    count = (len(values) - offset) // width
    if count * chips * spreading_factor > MAX_ACQUISITION_WORK:
        raise RFDemodError("LoRa FFT work cap exceeded")
    reference = _lora_chirp(chips, down=downchirp)
    bins = []
    for symbol in range(count):
        start = offset + symbol * width
        block = _collapse_chips(values[start:start + width], chips, samples_per_chip)
        dechirped = [block[index] * reference[index].conjugate() for index in range(chips)]
        spectrum = sdr._fft(dechirped)
        bins.append(max(range(chips), key=lambda index: abs(spectrum[index]) ** 2))
    return bins


def _circular_distance(left: int, right: int, modulus: int) -> int:
    distance = abs(left - right) % modulus
    return min(distance, modulus - distance)


def find_lora_preamble(symbols: Sequence[int], spreading_factor: int, *, minimum: int = 6, tolerance: int = 1) -> dict[str, Any] | None:
    chips = 1 << spreading_factor
    if not 2 <= minimum <= 64 or not 0 <= tolerance <= chips // 4:
        raise RFDemodError("invalid LoRa preamble search")
    values = [int(symbol) for symbol in symbols]
    if any(not 0 <= symbol < chips for symbol in values):
        raise RFDemodError("LoRa symbol outside spreading-factor range")
    best = None
    for start in range(len(values)):
        anchor = values[start]
        run = [0]
        for symbol in values[start + 1:]:
            delta = ((symbol - anchor + chips // 2) % chips) - chips // 2
            reference_delta = round(statistics.median(run))
            if abs(delta - reference_delta) > tolerance:
                break
            run.append(delta)
        if len(run) >= minimum and (best is None or len(run) > best[1]):
            best = start, len(run), (anchor + round(statistics.median(run))) % chips
    if best is None:
        return None
    return {"start_symbol": best[0], "length": best[1], "frequency_offset_bins": best[2]}


def acquire_lora(
    iq: Sequence[complex], spreading_factor: int, *, samples_per_chip: int = 1,
    timing_offset: int | None = None, minimum_preamble: int = 6,
) -> dict[str, Any]:
    """Search symbol timing and repeated upchirps; report CFO-corrected raw symbol bins."""
    if not 5 <= spreading_factor <= 12 or not 1 <= samples_per_chip <= 64:
        raise RFDemodError("invalid LoRa spreading factor or oversampling")
    values = _complex_samples(iq)
    chips, width = 1 << spreading_factor, (1 << spreading_factor) * samples_per_chip
    if timing_offset is None:
        candidate_offsets = range(0, width, samples_per_chip)
        estimated = len(candidate_offsets) * min(16, max(1, len(values) // width)) * chips * spreading_factor
        if estimated > MAX_ACQUISITION_WORK:
            raise RFDemodError("LoRa timing search exceeds work cap; supply timing_offset")
    else:
        candidate_offsets = (timing_offset,)
    best = None
    for offset in candidate_offsets:
        symbols = lora_symbol_bins(values, spreading_factor, samples_per_chip=samples_per_chip, offset=offset)
        preamble = find_lora_preamble(symbols, spreading_factor, minimum=minimum_preamble)
        score = (preamble["length"] if preamble else 0, -offset)
        if best is None or score > best[0]:
            best = score, offset, symbols, preamble
    if best is None or best[3] is None:
        return {"acquired": False, "spreading_factor": spreading_factor, "samples_per_chip": samples_per_chip}
    _, offset, symbols, preamble = best
    cfo = preamble["frequency_offset_bins"]
    corrected = [(symbol - cfo) % chips for symbol in symbols]
    return {
        "acquired": True, "spreading_factor": spreading_factor, "samples_per_chip": samples_per_chip,
        "timing_offset": offset, "preamble": preamble, "symbols": symbols,
        "corrected_symbols": corrected,
    }


def gray_decode(value: int) -> int:
    if value < 0:
        raise RFDemodError("negative Gray value")
    decoded = value
    shift = value >> 1
    while shift:
        decoded ^= shift
        shift >>= 1
    return decoded


def lora_hamming_encode(nibble: int, coding_rate: int = 4) -> int:
    if not 0 <= nibble < 16 or not 1 <= coding_rate <= 4:
        raise RFDemodError("LoRa nibble/coding rate outside range")
    d0, d1, d2, d3 = ((nibble >> bit) & 1 for bit in range(4))
    parity = (d0 ^ d1 ^ d2, d1 ^ d2 ^ d3, d0 ^ d1 ^ d3, d0 ^ d2 ^ d3)
    codeword = nibble
    for index in range(coding_rate):
        codeword |= parity[index] << (4 + index)
    return codeword


def lora_hamming_decode(codeword: int, coding_rate: int = 4) -> dict[str, Any]:
    if not 1 <= coding_rate <= 4 or not 0 <= codeword < (1 << (4 + coding_rate)):
        raise RFDemodError("LoRa codeword/coding rate outside range")
    candidates = [(int((codeword ^ lora_hamming_encode(nibble, coding_rate)).bit_count()), nibble)
                  for nibble in range(16)]
    distance = min(row[0] for row in candidates)
    matches = [nibble for candidate_distance, nibble in candidates if candidate_distance == distance]
    correctable = distance == 0 or (coding_rate >= 3 and distance == 1 and len(matches) == 1)
    return {"nibble": matches[0] if correctable else None, "distance": distance,
            "corrected": distance == 1 and correctable, "valid": correctable, "ambiguous": len(matches) != 1}


def lora_deinterleave(symbols: Sequence[int], spreading_factor: int, coding_rate: int = 4, *, gray: bool = True) -> list[int]:
    """Diagonal-deinterleave complete LoRa blocks into ``SF`` Hamming codewords."""
    if not 5 <= spreading_factor <= 12 or not 1 <= coding_rate <= 4:
        raise RFDemodError("invalid LoRa deinterleave configuration")
    width = 4 + coding_rate
    values = [int(symbol) for symbol in symbols]
    if len(values) % width:
        raise RFDemodError("LoRa interleaver block is incomplete")
    limit = 1 << spreading_factor
    if any(not 0 <= symbol < limit for symbol in values):
        raise RFDemodError("LoRa interleaver symbol outside range")
    output = []
    for base in range(0, len(values), width):
        block = [gray_decode(value) if gray else value for value in values[base:base + width]]
        codewords = [0] * spreading_factor
        for row, symbol in enumerate(block):
            for column in range(spreading_factor):
                # LoRa's diagonal interleaver rotates row j by (i-j-1) at column i.
                codewords[column] |= ((symbol >> ((column - row - 1) % spreading_factor)) & 1) << row
        output.extend(codewords)
    return output


def decode_lora_codewords(symbols: Sequence[int], spreading_factor: int, coding_rate: int = 4, *, gray: bool = True) -> dict[str, Any]:
    codewords = lora_deinterleave(symbols, spreading_factor, coding_rate, gray=gray)
    decoded = [lora_hamming_decode(codeword, coding_rate) for codeword in codewords]
    nibbles = [row["nibble"] for row in decoded]
    payload = bytearray()
    for index in range(0, len(nibbles) - 1, 2):
        if nibbles[index] is None or nibbles[index + 1] is None:
            continue
        payload.append(int(nibbles[index]) | (int(nibbles[index + 1]) << 4))
    return {"codewords": codewords, "decoded": decoded, "nibbles": nibbles,
            "payload": bytes(payload), "uncorrectable": sum(not row["valid"] for row in decoded)}


def parse_lora_explicit_header(header: bytes) -> dict[str, Any]:
    """Interpret the 20 meaningful bits of a deinterleaved explicit PHY header."""
    if not isinstance(header, bytes) or len(header) != 3:
        raise RFDemodError("LoRa explicit header must be exactly three bytes")
    coding = (header[1] >> 5) & 7
    return {"payload_length": header[0], "coding_rate": coding + 4 if 1 <= coding <= 4 else None,
            "payload_crc": bool(header[1] & 0x10), "reserved": header[1] & 0x0F,
            "header_checksum": header[2] >> 3, "raw": header.hex()}


# ------------------------------------------------------------------ POCSAG and AIS acquisition

def _best_sync_distance(bits: str, sync: str) -> tuple[int, int | None]:
    if len(bits) < len(sync):
        return len(sync) + 1, None
    best = min((sum(left != right for left, right in zip(bits[offset:offset + len(sync)], sync)), offset)
               for offset in range(len(bits) - len(sync) + 1))
    return best


def acquire_pocsag(
    iq: Sequence[complex], sample_rate: float, *, baud_candidates: Sequence[int] = (512, 1200, 2400),
    max_sync_errors: int = 2, max_bch_errors: int = 2,
) -> dict[str, Any]:
    """Search standard POCSAG rates/polarities, then perform BCH/message decoding."""
    if not 0 <= max_sync_errors <= 8:
        raise RFDemodError("invalid POCSAG sync error allowance")
    sync = f"{sdr.POCSAG_SYNC:032b}"
    candidates = []
    for baud in baud_candidates:
        try:
            demod = gfsk_demodulate(iq, sample_rate, float(baud), matched_filter=False)
        except RFDemodError:
            continue
        for invert in (False, True):
            bits = demod["bits"] if not invert else bits_invert(demod["bits"])
            distance, offset = _best_sync_distance(bits, sync)
            messages = sdr.decode_pocsag_bits(bits, max_errors=max_bch_errors) if distance <= max_sync_errors else []
            candidates.append((distance, -len(messages), baud, invert, offset, bits, messages, demod))
    if not candidates:
        raise RFDemodError("no valid POCSAG baud candidate")
    distance, _, baud, invert, offset, bits, messages, demod = min(candidates, key=lambda row: row[:4])
    return {"acquired": distance <= max_sync_errors, "baud": baud, "inverted": invert,
            "sync_offset": offset, "sync_distance": distance, "bits": bits,
            "messages": messages, "timing_offset": demod["timing_offset"], "eye_opening": demod["eye_opening"]}


def acquire_pocsag_audio(
    samples: Sequence[float], sample_rate: float, *, baud_candidates: Sequence[int] = (512, 1200, 2400),
    max_sync_errors: int = 2, max_bch_errors: int = 2,
) -> dict[str, Any]:
    """Acquire POCSAG from a saved real discriminator stream such as a mono WAV."""
    if not 0 <= max_sync_errors <= 8:
        raise RFDemodError("invalid POCSAG sync error allowance")
    sync, candidates = f"{sdr.POCSAG_SYNC:032b}", []
    for baud in baud_candidates:
        try:
            demod = level_demodulate(samples, sample_rate, float(baud))
        except RFDemodError:
            continue
        for invert in (False, True):
            bits = demod["bits"] if not invert else bits_invert(demod["bits"])
            distance, offset = _best_sync_distance(bits, sync)
            messages = sdr.decode_pocsag_bits(bits, max_errors=max_bch_errors) if distance <= max_sync_errors else []
            candidates.append((distance, -len(messages), baud, invert, offset, bits, messages, demod))
    if not candidates:
        raise RFDemodError("no valid POCSAG audio baud candidate")
    distance, _, baud, invert, offset, bits, messages, demod = min(candidates, key=lambda row: row[:4])
    return {"acquired": distance <= max_sync_errors, "baud": baud, "inverted": invert,
            "sync_offset": offset, "sync_distance": distance, "bits": bits, "messages": messages,
            "timing_offset": demod["timing_offset"], "eye_opening": demod["eye_opening"]}


def decode_pocsag_wav(data: bytes, *, channel: int = 0, **kwargs: Any) -> dict[str, Any]:
    try:
        samples, rate = sdr.load_wav(data, channel=channel)
    except sdr.SDRDecodeError as exc:
        raise RFDemodError(str(exc)) from exc
    return acquire_pocsag_audio(samples, rate, **kwargs)


def bits_invert(bits: str) -> str:
    if len(bits) > MAX_BITS or set(bits) - {"0", "1"}:
        raise RFDemodError("invalid binary string")
    return bits.translate(str.maketrans("01", "10"))


def acquire_ais(iq: Sequence[complex], sample_rate: float, *, baud: int = 9600) -> dict[str, Any]:
    """Acquire saved AIS GMSK polarity/NRZI state and rank CRC-valid HDLC frames."""
    demod = gfsk_demodulate(iq, sample_rate, float(baud), bt=0.4, matched_filter=False)
    candidates = []
    for invert in (False, True):
        levels = demod["bits"] if not invert else bits_invert(demod["bits"])
        for initial in ("0", "1"):
            frames = sdr.decode_ais_levels(levels, initial_level=initial)
            good = sum(bool(frame.get("crc_ok")) for frame in frames)
            candidates.append((good, len(frames), not invert, initial, levels, frames))
    good, _, not_inverted, initial, levels, frames = max(candidates, key=lambda row: row[:3])
    return {"acquired": bool(frames), "crc_valid_frames": good, "inverted": not not_inverted,
            "initial_level": initial, "levels": levels, "frames": frames,
            "timing_offset": demod["timing_offset"], "eye_opening": demod["eye_opening"]}


def acquire_ais_audio(samples: Sequence[float], sample_rate: float, *, baud: int = 9600) -> dict[str, Any]:
    """Acquire AIS from a saved mono GMSK discriminator stream."""
    demod = level_demodulate(samples, sample_rate, float(baud))
    candidates = []
    for invert in (False, True):
        levels = demod["bits"] if not invert else bits_invert(demod["bits"])
        for initial in ("0", "1"):
            frames = sdr.decode_ais_levels(levels, initial_level=initial)
            good = sum(bool(frame.get("crc_ok")) for frame in frames)
            candidates.append((good, len(frames), not invert, initial, levels, frames))
    good, _, not_inverted, initial, levels, frames = max(candidates, key=lambda row: row[:3])
    return {"acquired": bool(frames), "crc_valid_frames": good, "inverted": not not_inverted,
            "initial_level": initial, "levels": levels, "frames": frames,
            "timing_offset": demod["timing_offset"], "eye_opening": demod["eye_opening"]}


def decode_ais_wav(data: bytes, *, channel: int = 0, **kwargs: Any) -> dict[str, Any]:
    try:
        samples, rate = sdr.load_wav(data, channel=channel)
    except sdr.SDRDecodeError as exc:
        raise RFDemodError(str(exc)) from exc
    return acquire_ais_audio(samples, rate, **kwargs)


def decode_lora_wav(data: bytes, spreading_factor: int, *, i_channel: int = 0, q_channel: int = 1,
                    **kwargs: Any) -> dict[str, Any]:
    iq, _ = load_stereo_iq_wav(data, i_channel=i_channel, q_channel=q_channel)
    return acquire_lora(iq, spreading_factor, **kwargs)


# ------------------------------------------------------------------ GPS/GNSS

GPS_G2_TAPS = {
    1: (2, 6), 2: (3, 7), 3: (4, 8), 4: (5, 9), 5: (1, 9), 6: (2, 10), 7: (1, 8), 8: (2, 9),
    9: (3, 10), 10: (2, 3), 11: (3, 4), 12: (5, 6), 13: (6, 7), 14: (7, 8), 15: (8, 9), 16: (9, 10),
    17: (1, 4), 18: (2, 5), 19: (3, 6), 20: (4, 7), 21: (5, 8), 22: (6, 9), 23: (1, 3), 24: (4, 6),
    25: (5, 7), 26: (6, 8), 27: (7, 9), 28: (8, 10), 29: (1, 6), 30: (2, 7), 31: (3, 8), 32: (4, 9),
}


def gps_ca_code(prn: int, *, bipolar: bool = True) -> list[int]:
    """Generate one 1023-chip GPS L1 C/A Gold code for PRN 1..32."""
    if prn not in GPS_G2_TAPS:
        raise RFDemodError("GPS C/A PRN must be 1..32")
    tap_a, tap_b = GPS_G2_TAPS[prn]
    g1, g2, output = [1] * 10, [1] * 10, []
    for _ in range(1023):
        bit = g1[9] ^ g2[tap_a - 1] ^ g2[tap_b - 1]
        output.append((1 if bit == 0 else -1) if bipolar else bit)
        g1_feedback = g1[2] ^ g1[9]
        g2_feedback = g2[1] ^ g2[2] ^ g2[5] ^ g2[7] ^ g2[8] ^ g2[9]
        g1 = [g1_feedback] + g1[:-1]
        g2 = [g2_feedback] + g2[:-1]
    return output


def acquire_gps_ca(
    iq: Sequence[complex], sample_rate: float, prns: Iterable[int], *, if_hz: float = 0.0,
    doppler_bins: Sequence[float] = (0.0,), threshold_ratio: float = 2.5,
) -> list[dict[str, Any]]:
    """Perform bounded one-millisecond serial GPS C/A code/Doppler acquisition."""
    values = _complex_samples(iq)
    rate, intermediate = _finite(sample_rate, "sample rate"), _finite(if_hz, "IF")
    if rate < GPS_CA_RATE or rate > 20_000_000:
        raise RFDemodError("GPS acquisition sample rate must be 1.023..20 MHz")
    sample_count = int(round(rate / 1000.0))
    if len(values) < sample_count:
        raise RFDemodError("GPS acquisition needs at least one millisecond")
    values = values[:sample_count]
    prn_values = list(prns)
    if not prn_values or len(prn_values) > 32:
        raise RFDemodError("GPS acquisition needs 1..32 PRNs")
    dopplers = [_finite(value, "Doppler bin") for value in doppler_bins]
    threshold_ratio = _finite(threshold_ratio, "acquisition threshold")
    if not dopplers or threshold_ratio <= 0:
        raise RFDemodError("GPS acquisition needs Doppler bins and a positive threshold")
    work = sample_count * sample_count * len(prn_values) * len(dopplers)
    if work > MAX_ACQUISITION_WORK:
        raise RFDemodError("GPS serial correlation work cap exceeded")
    results = []
    samples_per_chip = rate / GPS_CA_RATE
    guard = max(1, int(math.ceil(samples_per_chip)))
    for prn in prn_values:
        chips = gps_ca_code(int(prn))
        sampled = [chips[int(index * GPS_CA_RATE / rate) % 1023] for index in range(sample_count)]
        best = None
        for doppler in dopplers:
            wiped = [value * cmath.exp(-2j * math.pi * (intermediate + doppler) * index / rate)
                      for index, value in enumerate(values)]
            powers = []
            for phase in range(sample_count):
                correlation = sum(wiped[index] * sampled[(index + phase) % sample_count] for index in range(sample_count))
                powers.append(abs(correlation) ** 2)
            peak_phase = max(range(sample_count), key=powers.__getitem__)
            peak = powers[peak_phase]
            sidelobes = [power for index, power in enumerate(powers)
                         if _circular_distance(index, peak_phase, sample_count) > guard]
            second = max(sidelobes) if sidelobes else 0.0
            ratio = peak / (second + 1e-30)
            candidate = (ratio, peak, doppler, peak_phase, second, statistics.median(powers))
            if best is None or candidate[:2] > best[:2]:
                best = candidate
        assert best is not None
        ratio, peak, doppler, phase, second, floor = best
        results.append({"prn": int(prn), "acquired": ratio >= threshold_ratio,
                        "doppler_hz": doppler, "code_phase_samples": phase,
                        "code_phase_chips": phase * GPS_CA_RATE / rate,
                        "peak_power": peak, "second_peak_power": second,
                        "peak_ratio": ratio, "noise_floor_power": floor})
    return results


def parse_gnss_capture(data: bytes, *, format: str = "auto") -> list[dict[str, Any]]:
    if not isinstance(data, bytes) or len(data) > sdr.MAX_BYTES:
        raise RFDemodError("GNSS capture must be bounded bytes")
    if format == "auto":
        format = "json" if data.lstrip().startswith((b"[", b"{")) else "csv"
    if format == "json":
        try:
            decoded = json.loads(data.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RFDemodError(f"invalid GNSS JSON: {exc}") from exc
        records = decoded.get("measurements") if isinstance(decoded, dict) else decoded
        if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
            raise RFDemodError("GNSS JSON must contain a measurement list")
        if len(records) > MAX_RECORDS:
            raise RFDemodError("GNSS record cap exceeded")
        return [dict(row) for row in records]
    if format != "csv":
        raise RFDemodError("GNSS format must be auto, json or csv")
    try:
        reader = csv.DictReader(io.StringIO(data.decode("utf-8")))
        rows = [dict(row) for row in reader]
    except (UnicodeError, csv.Error) as exc:
        raise RFDemodError(f"invalid GNSS CSV: {exc}") from exc
    if reader.fieldnames is None:
        raise RFDemodError("GNSS CSV lacks a header")
    numeric = {"time", "timestamp", "prn", "pseudorange_m", "doppler_hz", "cn0_dbhz", "latitude", "longitude", "altitude"}
    for row in rows:
        for key in numeric & row.keys():
            if row[key] not in (None, ""):
                try:
                    row[key] = float(row[key])
                except ValueError as exc:
                    raise RFDemodError(f"invalid numeric GNSS field {key}") from exc
    if len(rows) > MAX_RECORDS:
        raise RFDemodError("GNSS record cap exceeded")
    return rows


def _haversine_m(first: tuple[float, float], second: tuple[float, float]) -> float:
    lat1, lon1, lat2, lon2 = map(math.radians, (first[0], first[1], second[0], second[1]))
    dlat, dlon = lat2 - lat1, lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * 6_371_008.8 * math.asin(min(1.0, math.sqrt(a)))


def pseudorange_residuals(measurements: Sequence[dict[str, Any]], receiver_ecef: Sequence[float]) -> dict[str, Any]:
    if len(receiver_ecef) != 3:
        raise RFDemodError("receiver ECEF must contain x,y,z")
    receiver = tuple(_finite(value, "receiver ECEF") for value in receiver_ecef)
    rows = []
    for measurement in measurements:
        satellite = measurement.get("satellite_ecef")
        if not isinstance(satellite, (list, tuple)) or len(satellite) != 3 or "pseudorange_m" not in measurement:
            continue
        point = tuple(_finite(value, "satellite ECEF") for value in satellite)
        geometric = math.sqrt(sum((point[index] - receiver[index]) ** 2 for index in range(3)))
        observed = _finite(measurement["pseudorange_m"], "pseudorange")
        rows.append({"prn": measurement.get("prn"), "observed_m": observed, "geometric_m": geometric,
                     "raw_residual_m": observed - geometric})
    if not rows:
        return {"clock_bias_m": None, "residuals": [], "rms_m": None}
    clock = statistics.median(row["raw_residual_m"] for row in rows)
    for row in rows:
        row["residual_m"] = row["raw_residual_m"] - clock
    rms = math.sqrt(sum(row["residual_m"] ** 2 for row in rows) / len(rows))
    return {"clock_bias_m": clock, "residuals": rows, "rms_m": rms}


def analyze_gnss_measurements(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Find evidence of replay/spoofing in supplied receiver measurements, never claim intent."""
    rows = []
    for index, source in enumerate(records):
        if index >= MAX_RECORDS or not isinstance(source, dict):
            raise RFDemodError("invalid or excessive GNSS measurement records")
        row = dict(source)
        time_key = "time" if "time" in row else "timestamp"
        if time_key not in row or "prn" not in row:
            raise RFDemodError("GNSS measurement lacks time/PRN")
        row["_time"] = _finite(row[time_key], "GNSS time")
        row["_prn"] = int(_finite(row["prn"], "GNSS PRN"))
        rows.append(row)
    epochs: dict[float, list[dict[str, Any]]] = {}
    for row in rows:
        epochs.setdefault(row["_time"], []).append(row)
    findings = []
    for epoch, group in sorted(epochs.items()):
        prns = [row["_prn"] for row in group]
        duplicates = sorted(prn for prn, count in collections.Counter(prns).items() if count > 1)
        if duplicates:
            findings.append({"kind": "duplicate-satellite", "severity": "high", "time": epoch, "prns": duplicates})
        cn0 = [_finite(row["cn0_dbhz"], "C/N0") for row in group if "cn0_dbhz" in row]
        if len(cn0) >= 4 and statistics.pstdev(cn0) < 0.05:
            findings.append({"kind": "cn0-convergence", "severity": "medium", "time": epoch,
                             "count": len(cn0), "standard_deviation": statistics.pstdev(cn0)})
    ordered_epochs = sorted(epochs)
    for previous_time, current_time in zip(ordered_epochs, ordered_epochs[1:]):
        elapsed = current_time - previous_time
        if elapsed <= 0:
            continue
        previous = {row["_prn"]: row for row in epochs[previous_time]}
        current = {row["_prn"]: row for row in epochs[current_time]}
        common = sorted(set(previous) & set(current))
        deltas = []
        doppler_residuals = []
        for prn in common:
            if "pseudorange_m" not in previous[prn] or "pseudorange_m" not in current[prn]:
                continue
            delta = (_finite(current[prn]["pseudorange_m"], "pseudorange")
                     - _finite(previous[prn]["pseudorange_m"], "pseudorange"))
            deltas.append((prn, delta))
            if "doppler_hz" in previous[prn] and "doppler_hz" in current[prn]:
                doppler = (_finite(previous[prn]["doppler_hz"], "Doppler")
                           + _finite(current[prn]["doppler_hz"], "Doppler")) / 2.0
                predicted_rate = -doppler * SPEED_OF_LIGHT / GPS_L1_HZ
                doppler_residuals.append((prn, delta / elapsed - predicted_rate))
        if len(deltas) >= 4:
            median_delta = statistics.median(value for _, value in deltas)
            mad = statistics.median(abs(value - median_delta) for _, value in deltas)
            if abs(median_delta) > 1000.0 and mad < 10.0:
                findings.append({"kind": "common-code-phase-jump", "severity": "high",
                                 "from_time": previous_time, "to_time": current_time,
                                 "median_jump_m": median_delta, "mad_m": mad, "satellites": len(deltas)})
        bad_doppler = [{"prn": prn, "residual_mps": residual} for prn, residual in doppler_residuals if abs(residual) > 200.0]
        if len(bad_doppler) >= 3:
            findings.append({"kind": "doppler-code-inconsistency", "severity": "high",
                             "from_time": previous_time, "to_time": current_time, "residuals": bad_doppler})
        previous_positions = [(row["latitude"], row["longitude"]) for row in epochs[previous_time]
                              if "latitude" in row and "longitude" in row]
        current_positions = [(row["latitude"], row["longitude"]) for row in epochs[current_time]
                             if "latitude" in row and "longitude" in row]
        if previous_positions and current_positions:
            first = tuple(_finite(value, "position") for value in previous_positions[0])
            second = tuple(_finite(value, "position") for value in current_positions[0])
            speed = _haversine_m(first, second) / elapsed
            if speed > 1000.0:
                findings.append({"kind": "impossible-position-jump", "severity": "high",
                                 "from_time": previous_time, "to_time": current_time, "speed_mps": speed})
    return {"measurement_count": len(rows), "epoch_count": len(epochs), "findings": findings,
            "spoofing_indicators": sum(row["severity"] in {"high", "critical"} for row in findings)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="offline full RF/GNSS artifact analysis")
    parser.add_argument("mode", choices=("gnss", "gps-acquire", "lora", "pocsag", "ais"))
    parser.add_argument("artifact")
    parser.add_argument("--format", default="cu8")
    parser.add_argument("--sample-rate", type=float)
    parser.add_argument("--sf", type=int, default=7)
    parser.add_argument("--prn", type=int, action="append")
    args = parser.parse_args(argv)
    try:
        raw = Path(args.artifact).read_bytes()
        if len(raw) > sdr.MAX_BYTES:
            raise RFDemodError("artifact exceeds cap")
        if args.mode == "gnss":
            result: Any = analyze_gnss_measurements(parse_gnss_capture(raw))
        else:
            if args.sample_rate is None and args.format != "wav":
                raise RFDemodError("IQ modes require --sample-rate")
            if args.format == "wav" and args.mode in {"pocsag", "ais"}:
                result = decode_pocsag_wav(raw) if args.mode == "pocsag" else decode_ais_wav(raw)
                print(json.dumps(result, indent=2, sort_keys=True, default=lambda value: value.hex() if isinstance(value, bytes) else str(value)))
                return 0
            if args.format == "wav":
                iq, wav_rate = load_stereo_iq_wav(raw)
                if args.sample_rate is not None and abs(wav_rate - args.sample_rate) > 1e-9:
                    raise RFDemodError("--sample-rate conflicts with WAV metadata")
                effective_rate = float(wav_rate)
            else:
                iq = sdr.load_iq(raw, args.format)
                effective_rate = float(args.sample_rate)
            if args.mode == "gps-acquire":
                result = acquire_gps_ca(iq, effective_rate, args.prn or [1])
            elif args.mode == "lora":
                result = acquire_lora(iq, args.sf)
            elif args.mode == "pocsag":
                result = acquire_pocsag(iq, effective_rate)
            else:
                result = acquire_ais(iq, effective_rate)
        print(json.dumps(result, indent=2, sort_keys=True, default=lambda value: value.hex() if isinstance(value, bytes) else str(value)))
        return 0
    except (OSError, RFDemodError, sdr.SDRDecodeError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
