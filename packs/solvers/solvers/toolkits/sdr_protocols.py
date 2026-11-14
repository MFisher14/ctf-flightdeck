#!/usr/bin/env python3
"""Bounded, deterministic decoders for saved SDR IQ/WAV captures.

This module is deliberately offline.  It accepts bytes or already sampled arrays and never
opens a radio, sound device, interface, socket, or RPC endpoint.  The demodulators expose the
small protocol primitives useful in CTF artifacts: OOK/ASK, FSK/GFSK, LoRa chirp symbols,
Mode-S/ADS-B, POCSAG, AIS HDLC, and RDS groups.
"""
from __future__ import annotations

import argparse
import cmath
import io
import json
import math
import struct
import wave
from pathlib import Path
from typing import Iterable, Sequence


MAX_BYTES = 64 << 20
MAX_SAMPLES = 2_000_000
MAX_BITS = 8_000_000
MAX_FRAMES = 20_000
MAX_DFT_WORK = 4_000_000


class SDRDecodeError(ValueError):
    pass


def _bounded(seq: Iterable, cap: int, what: str) -> list:
    out = []
    for value in seq:
        if len(out) >= cap:
            raise SDRDecodeError(f"{what} exceeds cap {cap}")
        out.append(value)
    return out


def load_iq(data: bytes, fmt: str = "cu8") -> list[complex]:
    """Decode common interleaved IQ formats without consulting a device."""
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise SDRDecodeError("IQ input must be bounded bytes")
    fmt = fmt.lower().replace("-", "")
    out: list[complex] = []
    if fmt in {"cu8", "u8"}:
        if len(data) % 2:
            raise SDRDecodeError("interleaved CU8 data has an odd length")
        out = [complex((data[i] - 127.5) / 127.5, (data[i + 1] - 127.5) / 127.5)
               for i in range(0, len(data), 2)]
    elif fmt in {"cs8", "s8"}:
        if len(data) % 2:
            raise SDRDecodeError("interleaved CS8 data has an odd length")
        vals = struct.unpack(f"{len(data)}b", data)
        out = [complex(vals[i] / 128.0, vals[i + 1] / 128.0)
               for i in range(0, len(vals), 2)]
    elif fmt in {"cs16le", "s16le"}:
        if len(data) % 4:
            raise SDRDecodeError("interleaved CS16LE data is truncated")
        vals = struct.unpack(f"<{len(data) // 2}h", data)
        out = [complex(vals[i] / 32768.0, vals[i + 1] / 32768.0)
               for i in range(0, len(vals), 2)]
    elif fmt in {"cf32le", "f32le"}:
        if len(data) % 8:
            raise SDRDecodeError("interleaved CF32LE data is truncated")
        vals = struct.unpack(f"<{len(data) // 4}f", data)
        if not all(math.isfinite(v) for v in vals):
            raise SDRDecodeError("IQ contains a non-finite float")
        out = [complex(vals[i], vals[i + 1]) for i in range(0, len(vals), 2)]
    else:
        raise SDRDecodeError(f"unsupported IQ format: {fmt}")
    if len(out) > MAX_SAMPLES:
        raise SDRDecodeError("IQ sample cap exceeded")
    return out


def load_wav(data: bytes, *, channel: int = 0) -> tuple[list[float], int]:
    """Read mono or one selected channel from a PCM WAV blob."""
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise SDRDecodeError("WAV input must be bounded bytes")
    try:
        with wave.open(io.BytesIO(data), "rb") as wav:
            channels, width, rate, frames = (wav.getnchannels(), wav.getsampwidth(),
                                              wav.getframerate(), wav.getnframes())
            if channels < 1 or not 0 <= channel < channels or width not in (1, 2, 3, 4):
                raise SDRDecodeError("unsupported WAV layout")
            if frames > MAX_SAMPLES:
                raise SDRDecodeError("WAV sample cap exceeded")
            raw = wav.readframes(frames)
    except (wave.Error, EOFError) as exc:
        raise SDRDecodeError(f"invalid WAV: {exc}") from exc
    values: list[float] = []
    stride = channels * width
    for base in range(0, len(raw) - stride + 1, stride):
        item = raw[base + channel * width:base + (channel + 1) * width]
        if width == 1:
            value, scale = item[0] - 128, 128.0
        elif width == 3:
            value = int.from_bytes(item, "little", signed=False)
            if value & 0x800000:
                value -= 1 << 24
            scale = float(1 << 23)
        else:
            value = int.from_bytes(item, "little", signed=True)
            scale = float(1 << (width * 8 - 1))
        values.append(value / scale)
    return values, rate


def moving_average(values: Sequence[float], width: int) -> list[float]:
    if not 1 <= width <= 65536:
        raise SDRDecodeError("invalid smoothing width")
    if len(values) > MAX_SAMPLES:
        raise SDRDecodeError("sample cap exceeded")
    total = 0.0
    out: list[float] = []
    for index, value in enumerate(values):
        if not math.isfinite(float(value)):
            raise SDRDecodeError("non-finite sample")
        total += float(value)
        if index >= width:
            total -= float(values[index - width])
        out.append(total / min(index + 1, width))
    return out


def magnitude(iq: Sequence[complex], *, smooth: int = 1) -> list[float]:
    if len(iq) > MAX_SAMPLES:
        raise SDRDecodeError("sample cap exceeded")
    values = [abs(complex(v)) for v in iq]
    return moving_average(values, smooth) if smooth > 1 else values


def ook_bits(samples: Sequence[float | complex], samples_per_symbol: int, *,
             threshold: float | None = None, offset: int = 0, invert: bool = False) -> str:
    """Hard-decision OOK/ASK demodulation at known symbol timing."""
    if not 1 <= samples_per_symbol <= 1_000_000 or not 0 <= offset < samples_per_symbol:
        raise SDRDecodeError("invalid OOK timing")
    if len(samples) > MAX_SAMPLES:
        raise SDRDecodeError("sample cap exceeded")
    power = [abs(complex(v)) for v in samples]
    if not power:
        return ""
    if threshold is None:
        ordered = sorted(power)
        lo = ordered[len(ordered) // 10]
        hi = ordered[(len(ordered) * 9) // 10]
        threshold = (lo + hi) / 2.0
    bits = []
    for start in range(offset, len(power) - samples_per_symbol + 1, samples_per_symbol):
        level = sum(power[start:start + samples_per_symbol]) / samples_per_symbol >= threshold
        bits.append("1" if level ^ invert else "0")
    return "".join(bits)


def quadrature_discriminator(iq: Sequence[complex]) -> list[float]:
    """Instantaneous phase difference in radians, robust across phase wrapping."""
    if len(iq) > MAX_SAMPLES:
        raise SDRDecodeError("sample cap exceeded")
    if len(iq) < 2:
        return []
    out = []
    previous = complex(iq[0])
    for current_value in iq[1:]:
        current = complex(current_value)
        product = current * previous.conjugate()
        out.append(math.atan2(product.imag, product.real))
        previous = current
    return out


def fsk_bits(iq: Sequence[complex], sample_rate: float, baud: float, *,
             offset: int = 0, gaussian_width: int = 1, invert: bool = False,
             decision_center: float | None = None) -> str:
    """Binary FSK/GFSK hard decisions from complex baseband.

    GFSK is selected by a ``gaussian_width`` larger than one; this smooths the frequency
    discriminator before symbol integration and avoids pretending to recover an RF carrier.
    """
    if not (math.isfinite(sample_rate) and math.isfinite(baud) and sample_rate > 0 and baud > 0):
        raise SDRDecodeError("invalid sample rate or baud")
    ratio = sample_rate / baud
    if not math.isfinite(ratio):
        raise SDRDecodeError("sample rate to baud ratio is not finite")
    sps = int(round(ratio))
    if not 2 <= sps <= 1_000_000 or not 0 <= offset < sps:
        raise SDRDecodeError("unsupported FSK samples-per-symbol")
    freq = quadrature_discriminator(iq)
    if gaussian_width > 1:
        freq = moving_average(freq, gaussian_width)
    if not freq:
        return ""
    if decision_center is None:
        # Estimate the midpoint of the two occupied tones while resisting short transients.  A
        # configured center remains available for single-tone/all-zero artifacts, which cannot
        # identify their own missing second tone.
        ordered = sorted(freq)
        center = (ordered[len(ordered) // 10] + ordered[(len(ordered) * 9) // 10]) / 2.0
    elif math.isfinite(decision_center):
        center = decision_center
    else:
        raise SDRDecodeError("non-finite FSK decision center")
    bits = []
    for start in range(offset, len(freq) - sps + 1, sps):
        high = sum(freq[start:start + sps]) / sps >= center
        bits.append("1" if high ^ invert else "0")
    return "".join(bits)


def _lora_upchirp(count: int) -> list[complex]:
    return [cmath.exp(2j * math.pi * ((k * k) / (2.0 * count) - k / 2.0))
            for k in range(count)]


def _fft(values: Sequence[complex]) -> list[complex]:
    """In-place-style radix-2 FFT returned as a new list."""
    count = len(values)
    if count < 1 or count & (count - 1):
        raise SDRDecodeError("FFT length must be a non-zero power of two")
    out = [complex(value) for value in values]
    j = 0
    for i in range(1, count):
        bit = count >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            out[i], out[j] = out[j], out[i]
    length = 2
    while length <= count:
        root = cmath.exp(-2j * math.pi / length)
        half = length // 2
        for start in range(0, count, length):
            phase = 1 + 0j
            for offset in range(half):
                even = out[start + offset]
                odd = out[start + offset + half] * phase
                out[start + offset] = even + odd
                out[start + offset + half] = even - odd
                phase *= root
        length <<= 1
    return out


def lora_symbols(iq: Sequence[complex], spreading_factor: int, *,
                 samples_per_symbol: int | None = None, downchirp: bool = False) -> list[int]:
    """Recover raw LoRa chirp-bin symbols by dechirp + bounded DFT.

    This intentionally stops at raw symbols: coding rate, whitening, interleaving, and header
    mode are configuration-dependent and must not be guessed from an artifact.
    """
    if not 5 <= spreading_factor <= 12:
        raise SDRDecodeError("LoRa spreading factor must be 5..12")
    bins = 1 << spreading_factor
    n = bins if samples_per_symbol is None else samples_per_symbol
    if n != bins:
        raise SDRDecodeError("only one-sample-per-chip LoRa captures are accepted")
    symbols = len(iq) // n
    if len(iq) > MAX_SAMPLES or symbols * n * spreading_factor > MAX_DFT_WORK:
        raise SDRDecodeError("LoRa FFT work cap exceeded")
    reference = _lora_upchirp(n)
    if downchirp:
        reference = [v.conjugate() for v in reference]
    out = []
    for symbol_index in range(symbols):
        block = iq[symbol_index * n:(symbol_index + 1) * n]
        dechirped = [complex(block[k]) * reference[k].conjugate() for k in range(n)]
        spectrum = _fft(dechirped)
        best_bin = max(range(n), key=lambda candidate:
                       spectrum[candidate].real ** 2 + spectrum[candidate].imag ** 2)
        out.append(best_bin)
    return out


def _poly_remainder(value: int, width: int, polynomial: int, degree: int) -> int:
    for bit in range(width - 1, degree - 1, -1):
        if value & (1 << bit):
            value ^= polynomial << (bit - degree)
    return value & ((1 << degree) - 1)


MODE_S_POLY = 0x1FFF409


def modes_crc(frame: bytes) -> int:
    if len(frame) not in (7, 14):
        raise SDRDecodeError("Mode-S frame must be 56 or 112 bits")
    return _poly_remainder(int.from_bytes(frame, "big"), len(frame) * 8, MODE_S_POLY, 24)


_CALLSIGN = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ#####_###############0123456789######"


def parse_adsb_frame(frame: bytes) -> dict:
    """Parse a structurally complete Mode-S frame; CRC status is always explicit."""
    if not isinstance(frame, bytes) or len(frame) not in (7, 14):
        raise SDRDecodeError("Mode-S frame must be 7 or 14 bytes")
    bits = "".join(f"{byte:08b}" for byte in frame)
    df = int(bits[:5], 2)
    out: dict = {"protocol": "mode-s", "df": df, "length": len(frame) * 8,
                 "crc_remainder": modes_crc(frame), "crc_ok": modes_crc(frame) == 0,
                 "parity": frame[-3:].hex()}
    if len(frame) == 14:
        out["capability"] = int(bits[5:8], 2)
        out["icao"] = frame[1:4].hex().upper()
    if df in (17, 18) and len(frame) == 14:
        type_code = int(bits[32:37], 2)
        out["type_code"] = type_code
        if 1 <= type_code <= 4:
            chars = [int(bits[pos:pos + 6], 2) for pos in range(40, 88, 6)]
            out["callsign"] = "".join(_CALLSIGN[v] if v < len(_CALLSIGN) else "#"
                                      for v in chars).replace("_", " ").strip(" #")
            out["emitter_category"] = int(bits[37:40], 2)
        elif 9 <= type_code <= 18:
            q = bits[47] == "1"
            raw_alt = int(bits[40:47] + bits[48:52], 2)
            out["altitude_feet"] = raw_alt * 25 - 1000 if q else None
            out["cpr_odd"] = bits[53] == "1"
            out["cpr_latitude"] = int(bits[54:71], 2)
            out["cpr_longitude"] = int(bits[71:88], 2)
        elif type_code == 19:
            subtype = int(bits[37:40], 2)
            out["velocity_subtype"] = subtype
            if subtype in (1, 2):
                scale = 4 if subtype == 2 else 1
                ew = max(0, int(bits[46:56], 2) - 1) * scale
                ns = max(0, int(bits[57:67], 2) - 1) * scale
                out["east_west_knots"] = -ew if bits[45] == "1" else ew
                out["north_south_knots"] = -ns if bits[56] == "1" else ns
    return out


_ADSB_PREAMBLE = {0, 2, 7, 9}


def decode_adsb_magnitude(samples: Sequence[float], *, samples_per_half: int = 1) -> list[dict]:
    """Find 8 us Mode-S preambles and PPM-decode saved magnitude samples."""
    if len(samples) > MAX_SAMPLES or not 1 <= samples_per_half <= 128:
        raise SDRDecodeError("invalid ADS-B sample input")
    half = samples_per_half
    short_need = (16 + 56 * 2) * half
    frames = []
    index = 0
    if any(not math.isfinite(float(value)) for value in samples):
        raise SDRDecodeError("ADS-B magnitude contains a non-finite sample")
    while index + short_need <= len(samples) and len(frames) < MAX_FRAMES:
        means = [sum(float(v) for v in samples[index + slot * half:index + (slot + 1) * half]) / half
                 for slot in range(16)]
        highs = sorted(means, reverse=True)[:4]
        lows = [means[pos] for pos in range(16) if pos not in _ADSB_PREAMBLE]
        threshold = (min(highs) + max(lows)) / 2.0 if highs and lows else 0.0
        if all(means[pos] > threshold for pos in _ADSB_PREAMBLE) and all(
                means[pos] < threshold for pos in range(16) if pos not in _ADSB_PREAMBLE):
            bit_values = []
            ambiguous = False
            base = index + 16 * half
            # Five bits determine DF and therefore the complete 56/112-bit frame length.
            target_bits = 112
            for bit in range(112):
                if base + (bit * 2 + 2) * half > len(samples):
                    ambiguous = True
                    break
                first = sum(float(v) for v in samples[base + bit * 2 * half:
                                                       base + (bit * 2 + 1) * half])
                second = sum(float(v) for v in samples[base + (bit * 2 + 1) * half:
                                                        base + (bit * 2 + 2) * half])
                if first == second:
                    ambiguous = True
                    break
                bit_values.append(1 if first > second else 0)
                if bit == 4:
                    df = sum(bit_values[pos] << (4 - pos) for pos in range(5))
                    target_bits = 112 if df in {16, 17, 18, 19, 20, 21, 24} else 56
                if len(bit_values) == target_bits:
                    break
            if not ambiguous:
                raw = bytes(sum(bit_values[i + j] << (7 - j) for j in range(8))
                            for i in range(0, target_bits, 8))
                length = target_bits // 8
                report = parse_adsb_frame(raw)
                report["sample_offset"] = index
                frames.append(report)
                index += (16 + length * 16) * half
                continue
        index += half
    return frames


POCSAG_SYNC = 0x7CD215D8
POCSAG_IDLE = 0x7A89C197
POCSAG_POLY = 0x769


def _pocsag_valid(word: int) -> bool:
    return (word.bit_count() & 1) == 0 and _poly_remainder(word >> 1, 31, POCSAG_POLY, 10) == 0


def correct_pocsag_codeword(word: int, *, max_errors: int = 2) -> tuple[int | None, list[int]]:
    """Validate/correct the BCH(31,21)+parity code.  Returns corrected word and bit indices."""
    if not 0 <= word <= 0xFFFFFFFF or max_errors not in (0, 1, 2):
        raise SDRDecodeError("invalid POCSAG codeword")
    if _pocsag_valid(word):
        return word, []
    if max_errors >= 1:
        for first in range(32):
            candidate = word ^ (1 << first)
            if _pocsag_valid(candidate):
                return candidate, [first]
    if max_errors >= 2:
        for first in range(32):
            for second in range(first + 1, 32):
                candidate = word ^ (1 << first) ^ (1 << second)
                if _pocsag_valid(candidate):
                    return candidate, [first, second]
    return None, []


def _pocsag_text(payloads: list[int]) -> dict:
    bits = "".join(f"{value:020b}" for value in payloads)
    chars = []
    for pos in range(0, len(bits) - 6, 7):
        value = int(bits[pos:pos + 7][::-1], 2)
        chars.append(chr(value) if value in (9, 10, 13) or 32 <= value < 127 else "\ufffd")
    numeric_map = "0123456789*U -)("
    digits = []
    for pos in range(0, len(bits) - 3, 4):
        value = int(bits[pos:pos + 4][::-1], 2)
        digits.append(numeric_map[value])
    return {"alphanumeric": "".join(chars).rstrip("\x00\ufffd"),
            "numeric": "".join(digits).rstrip()}


def decode_pocsag_bits(bits: str, *, max_errors: int = 2) -> list[dict]:
    if not isinstance(bits, str) or len(bits) > MAX_BITS or set(bits) - {"0", "1"}:
        raise SDRDecodeError("POCSAG input must be a bounded bit string")
    sync = f"{POCSAG_SYNC:032b}"
    start = bits.find(sync)
    if start < 0:
        return []
    pos = start + 32
    messages, active = [], None
    word_index = 0
    while pos + 32 <= len(bits) and len(messages) < MAX_FRAMES:
        raw = int(bits[pos:pos + 32], 2)
        pos += 32
        if raw == POCSAG_SYNC:
            word_index = 0
            continue
        if raw == POCSAG_IDLE:
            if active and active["payloads"]:
                active.update(_pocsag_text(active.pop("payloads")))
                messages.append(active)
                active = None
            word_index = (word_index + 1) % 16
            continue
        word, corrected = correct_pocsag_codeword(raw, max_errors=max_errors)
        if word is None:
            active = None
            word_index = (word_index + 1) % 16
            continue
        if not (word & 0x80000000):
            if active and active["payloads"]:
                active.update(_pocsag_text(active.pop("payloads")))
                messages.append(active)
            frame = word_index // 2
            active = {"address": (((word >> 13) & 0x3FFFF) << 3) | frame,
                      "function": (word >> 11) & 3, "payloads": [],
                      "corrected_bits": corrected}
        elif active is not None:
            active["payloads"].append((word >> 11) & 0xFFFFF)
            active["corrected_bits"] = active["corrected_bits"] + corrected
        word_index = (word_index + 1) % 16
    if active and active["payloads"]:
        active.update(_pocsag_text(active.pop("payloads")))
        messages.append(active)
    return messages


def decode_pocsag_iq(iq: Sequence[complex], sample_rate: float, baud: float = 1200,
                     *, offset: int = 0, invert: bool = False, max_errors: int = 2,
                     decision_center: float | None = None) -> list[dict]:
    """FSK-demodulate a configured saved POCSAG baseband capture, then BCH-decode it."""
    return decode_pocsag_bits(fsk_bits(iq, sample_rate, baud, offset=offset, invert=invert,
                                       decision_center=decision_center),
                              max_errors=max_errors)


def crc16_x25(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x8408 if crc & 1 else 0)
    return crc ^ 0xFFFF


def _unstuff_hdlc(bits: str) -> str | None:
    out, ones, pos = [], 0, 0
    while pos < len(bits):
        bit = bits[pos]
        out.append(bit)
        if bit == "1":
            ones += 1
            if ones > 5:
                return None
        else:
            if ones == 5:
                out.pop()
            ones = 0
        pos += 1
    return "".join(out)


def parse_ais_payload_bits(bits: str) -> dict:
    if not isinstance(bits, str) or set(bits) - {"0", "1"}:
        raise SDRDecodeError("AIS payload must be a binary string")
    if len(bits) < 38:
        return {"bits": bits}
    out = {"message_type": int(bits[0:6], 2), "repeat": int(bits[6:8], 2),
           "mmsi": int(bits[8:38], 2)}
    if out["message_type"] in (1, 2, 3) and len(bits) >= 168:
        def signed(part: str) -> int:
            value = int(part, 2)
            return value - (1 << len(part)) if value & (1 << (len(part) - 1)) else value
        longitude, latitude = signed(bits[61:89]), signed(bits[89:116])
        out["longitude"] = None if abs(longitude) >= 181 * 600000 else longitude / 600000.0
        out["latitude"] = None if abs(latitude) >= 91 * 600000 else latitude / 600000.0
        out["sog_knots"] = int(bits[50:60], 2) / 10.0
        out["cog_degrees"] = int(bits[116:128], 2) / 10.0
    return out


def decode_ais_levels(levels: str, *, initial_level: str = "0") -> list[dict]:
    """NRZI-decode, unstuff, CRC-check, and parse saved AIS discriminator levels."""
    if not isinstance(levels, str) or len(levels) > MAX_BITS or set(levels) - {"0", "1"}:
        raise SDRDecodeError("AIS levels must be a bounded bit string")
    previous = initial_level
    decoded = []
    for level in levels:
        decoded.append("1" if level == previous else "0")
        previous = level
    stream = "".join(decoded)
    flag = "01111110"  # temporal order before LSB byte packing
    positions = []
    cursor = 0
    while len(positions) <= MAX_FRAMES:
        found = stream.find(flag, cursor)
        if found < 0:
            break
        positions.append(found)
        cursor = found + 8
    frames = []
    for left, right in zip(positions, positions[1:]):
        stuffed = stream[left + 8:right]
        body = _unstuff_hdlc(stuffed)
        if body is None or len(body) < 24 or len(body) % 8:
            continue
        raw = bytes(sum(int(body[pos + bit]) << bit for bit in range(8))
                    for pos in range(0, len(body), 8))
        payload, supplied = raw[:-2], int.from_bytes(raw[-2:], "little")
        # HDLC was temporal LSB-first, but packing above restored each byte.  AIS fields occupy
        # those bytes MSB-first, so do not reverse the restored octets a second time.
        field_bits = "".join(f"{byte:08b}" for byte in payload)
        report = parse_ais_payload_bits(field_bits)
        report.update(raw=raw, crc=supplied, crc_ok=crc16_x25(payload) == supplied)
        frames.append(report)
    return frames


def decode_ais_iq(iq: Sequence[complex], sample_rate: float, baud: float = 9600, *,
                  offset: int = 0, gaussian_width: int = 3, invert: bool = False,
                  decision_center: float | None = None) -> list[dict]:
    """GMSK-discriminate configured saved AIS baseband into NRZI levels and HDLC frames."""
    levels = fsk_bits(iq, sample_rate, baud, offset=offset,
                      gaussian_width=gaussian_width, invert=invert,
                      decision_center=decision_center)
    return decode_ais_levels(levels)


RDS_POLY = 0x5B9
RDS_OFFSETS = {"A": 0x0FC, "B": 0x198, "C": 0x168, "C'": 0x350, "D": 0x1B4,
               "E": 0x000}


def rds_syndrome(block: int) -> int:
    if not 0 <= block < (1 << 26):
        raise SDRDecodeError("RDS block must contain 26 bits")
    return _poly_remainder(block, 26, RDS_POLY, 10)


def decode_rds_bits(bits: str) -> list[dict]:
    """Synchronize valid A/B/C-or-C'/D blocks and decode common group fields."""
    if not isinstance(bits, str) or len(bits) > MAX_BITS or set(bits) - {"0", "1"}:
        raise SDRDecodeError("RDS input must be a bounded bit string")
    groups = []
    pos = 0
    while pos + 104 <= len(bits) and len(groups) < MAX_FRAMES:
        blocks = [int(bits[pos + n * 26:pos + (n + 1) * 26], 2) for n in range(4)]
        syndromes = [rds_syndrome(block) for block in blocks]
        names = [next((name for name, value in RDS_OFFSETS.items() if value == syndrome), None)
                 for syndrome in syndromes]
        if names[0] == "A" and names[1] == "B" and names[2] in ("C", "C'") and names[3] == "D":
            data = [block >> 10 for block in blocks]
            group_type = (data[1] >> 12) & 0xF
            version = "B" if data[1] & 0x0800 else "A"
            row = {"offset": pos, "pi": data[0], "group_type": group_type,
                   "version": version, "pty": (data[1] >> 5) & 0x1F,
                   "traffic_program": bool(data[1] & 0x0400), "blocks": data}
            if group_type == 0:
                row["program_service_segment"] = (data[1] & 3,
                                                   bytes([(data[3] >> 8) & 0xFF,
                                                          data[3] & 0xFF]).decode("latin1"))
            if group_type == 2:
                chars = data[2:4] if version == "A" else data[3:4]
                row["radio_text_segment"] = (data[1] & 0xF, "".join(
                    bytes([(value >> 8) & 0xFF, value & 0xFF]).decode("latin1") for value in chars))
            groups.append(row)
            pos += 104
        else:
            pos += 1
    return groups


def rds_biphase_bits(samples: Sequence[float], samples_per_bit: int, *, offset: int = 0,
                     invert: bool = False, differential: bool = False,
                     previous_symbol: int = 0) -> str:
    """Decode the two half-symbol levels of a configured, clock-recovered RDS BPSK stream.

    Every valid biphase symbol has opposite half levels.  Invalid equal halves are represented
    by ``?`` so a damaged capture cannot silently turn into a valid group.
    """
    if (len(samples) > MAX_SAMPLES or not 2 <= samples_per_bit <= 1_000_000
            or samples_per_bit % 2 or not 0 <= offset < samples_per_bit):
        raise SDRDecodeError("invalid RDS biphase timing")
    if not samples:
        return ""
    if any(not math.isfinite(float(value)) for value in samples) or previous_symbol not in (0, 1):
        raise SDRDecodeError("invalid RDS biphase samples/state")
    ordered = sorted(float(value) for value in samples)
    threshold = (ordered[len(ordered) // 10] + ordered[(len(ordered) * 9) // 10]) / 2.0
    half = samples_per_bit // 2
    out = []
    for start in range(offset, len(samples) - samples_per_bit + 1, samples_per_bit):
        left = sum(float(v) for v in samples[start:start + half]) / half >= threshold
        right = sum(float(v) for v in samples[start + half:start + samples_per_bit]) / half >= threshold
        if left == right:
            out.append("?")
        else:
            out.append("1" if left ^ invert else "0")
    bits = "".join(out)
    if differential:
        decoded = []
        previous = previous_symbol
        for bit in bits:
            if bit == "?":
                decoded.append(bit)
                continue
            symbol = int(bit)
            decoded.append(str(symbol ^ previous))
            previous = symbol
        return "".join(decoded)
    return bits


def assemble_rds_groups(groups: Sequence[dict]) -> dict:
    """Assemble exact PS/RadioText segments from CRC-valid groups sharing one PI code."""
    by_pi: dict[int, dict] = {}
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("pi"), int):
            continue
        station = by_pi.setdefault(group["pi"], {"program_service_segments": {},
                                                 "radio_text_segments": {}})
        if "program_service_segment" in group:
            index, text = group["program_service_segment"]
            station["program_service_segments"][int(index)] = str(text)
        if "radio_text_segment" in group:
            index, text = group["radio_text_segment"]
            station["radio_text_segments"][int(index)] = str(text)
    out = {}
    for pi, station in sorted(by_pi.items()):
        ps = station.pop("program_service_segments")
        rt = station.pop("radio_text_segments")
        station["program_service"] = "".join(ps[index] for index in range(4)) if set(ps) >= set(range(4)) else None
        if rt:
            last = max(rt)
            station["radio_text"] = "".join(rt[index] for index in range(last + 1)) \
                if set(rt) >= set(range(last + 1)) else None
        else:
            station["radio_text"] = None
        out[f"{pi:04X}"] = station
    return out


def _jsonable(value):
    if isinstance(value, bytes):
        return value.hex()
    raise TypeError(type(value).__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="offline saved-capture SDR protocol decoder")
    parser.add_argument("protocol", choices=("adsb", "pocsag", "ais", "rds"))
    parser.add_argument("input", help="saved magnitude JSON (ADS-B) or ASCII bit/level file")
    parser.add_argument("--samples-per-half", type=int, default=1)
    args = parser.parse_args(argv)
    try:
        raw = Path(args.input).read_bytes()
        if len(raw) > MAX_BYTES:
            raise SDRDecodeError("input exceeds cap")
        if args.protocol == "adsb":
            samples = json.loads(raw.decode("utf-8"))
            result = decode_adsb_magnitude(samples, samples_per_half=args.samples_per_half)
        else:
            bits = "".join(raw.decode("ascii").split())
            result = {"pocsag": decode_pocsag_bits, "ais": decode_ais_levels,
                      "rds": decode_rds_bits}[args.protocol](bits)
        print(json.dumps(result, indent=2, default=_jsonable, sort_keys=True))
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, SDRDecodeError, TypeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
