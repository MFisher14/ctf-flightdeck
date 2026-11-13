#!/usr/bin/env python3
"""Pure-Python, CRC-gated BFSK and differential-BPSK decoding from saved PCM WAV bytes.

DTMF, AFSK/minimodem, SSTV and spectrogram workflows already live in ``carve_stego`` and
``stego_tools``.  This module adds deterministic symbol decoders for supplied modulation parameters.
It never opens an audio device.  A payload is returned only after the shared C5TG length+CRC frame
verifies; a strongest-frequency/phase guess by itself is never emitted.
"""
from __future__ import annotations

import argparse
import cmath
import importlib.util
import json
import math
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
MAX_AUDIO = 128 << 20
MAX_SECONDS = 300
MAX_SYMBOLS = 2_000_000


def _load(name, file):
    if name in sys.modules: return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    if spec is None or spec.loader is None: raise RuntimeError(f"cannot load {file}")
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module; spec.loader.exec_module(module)
    return module


audio = _load("csctf_audio_stego_for_signal", "audio_stego.py")
transform = _load("csctf_transform_stego_for_signal", "transform_stego.py")


class SignalError(ValueError):
    pass


def _mono(data: bytes):
    if not isinstance(data, bytes) or len(data) > MAX_AUDIO:
        raise SignalError("audio exceeds 128 MiB cap")
    parsed = audio.wav_channels(data)
    if parsed is None:
        raise SignalError("input is not bounded PCM WAV")
    info, channels = parsed
    rate = int(info.get("rate") or 0)
    if rate <= 0 or not channels or len(channels[0]) > rate * MAX_SECONDS:
        raise SignalError("invalid rate or duration exceeds 300 seconds")
    count = min(map(len, channels))
    values = []
    for index in range(count):
        sample = sum(channel[index] for channel in channels) / len(channels)
        if info["bits"] == 8: sample -= 128
        values.append(float(sample))
    return rate, values


def _corr(block, rate: int, frequency: float):
    step = -2j * math.pi * frequency / rate
    # Hann window reduces leakage while retaining phase for DBPSK.
    n = len(block)
    return sum(value * (0.5 - 0.5 * math.cos(2 * math.pi * index / max(1, n - 1)))
               * cmath.exp(step * index) for index, value in enumerate(block))


def _frame_from_bits(bits):
    """Find a unique verified frame over all bit offsets/polarities; ambiguity declines."""
    bits = [int(bit) & 1 for bit in bits]
    payloads = set()
    for invert in (0, 1):
        stream = [bit ^ invert for bit in bits]
        for offset in range(8):
            blob = bytearray()
            for at in range(offset, len(stream) - 7, 8):
                value = 0
                for bit in stream[at:at + 8]: value = (value << 1) | bit
                blob.append(value)
                if len(blob) > transform.MAX_PAYLOAD + transform.HEADER: break
            start = 0
            while True:
                found = bytes(blob).find(transform.MAGIC, start)
                if found < 0: break
                payload = transform.verify_frame(bytes(blob[found:]))
                if payload is not None: payloads.add(bytes(payload))
                start = found + 1
    return next(iter(payloads)) if len(payloads) == 1 else None


def bfsk_bits(samples, rate: int, baud: float, mark_hz: float, space_hz: float, *, sample_offset=0):
    if not 1 <= baud <= rate / 2 or not 0 < mark_hz < rate / 2 or not 0 < space_hz < rate / 2:
        raise SignalError("invalid BFSK frequencies/baud")
    sps = rate / baud
    if abs(sps - round(sps)) > 1e-9:
        raise SignalError("sample rate must be an integer multiple of baud")
    width = int(round(sps)); offset = int(sample_offset)
    if not 0 <= offset < width: raise SignalError("sample offset outside one symbol")
    symbols = (len(samples) - offset) // width
    if symbols > MAX_SYMBOLS: raise SignalError("symbol cap exceeded")
    bits = []
    for index in range(symbols):
        block = samples[offset + index * width:offset + (index + 1) * width]
        bits.append(1 if abs(_corr(block, rate, mark_hz)) >= abs(_corr(block, rate, space_hz)) else 0)
    return bits


def decode_bfsk(data: bytes, *, baud: float, mark_hz: float, space_hz: float, sample_offset=0):
    rate, samples = _mono(data)
    return _frame_from_bits(bfsk_bits(samples, rate, baud, mark_hz, space_hz,
                                      sample_offset=sample_offset))


def dbpsk_bits(samples, rate: int, baud: float, carrier_hz: float, *, sample_offset=0):
    if not 1 <= baud <= rate / 2 or not 0 < carrier_hz < rate / 2:
        raise SignalError("invalid DBPSK carrier/baud")
    sps = rate / baud
    if abs(sps - round(sps)) > 1e-9:
        raise SignalError("sample rate must be an integer multiple of baud")
    width, offset = int(round(sps)), int(sample_offset)
    if not 0 <= offset < width: raise SignalError("sample offset outside one symbol")
    symbols = (len(samples) - offset) // width
    if symbols > MAX_SYMBOLS: raise SignalError("symbol cap exceeded")
    phases = [_corr(samples[offset + index * width:offset + (index + 1) * width], rate, carrier_hz)
              for index in range(symbols)]
    # First symbol is the phase reference. A negative phase dot product means a pi transition.
    return [1 if (phases[index - 1].conjugate() * phases[index]).real < 0 else 0
            for index in range(1, len(phases))]


def decode_dbpsk(data: bytes, *, baud: float, carrier_hz: float, sample_offset=0):
    rate, samples = _mono(data)
    return _frame_from_bits(dbpsk_bits(samples, rate, baud, carrier_hz, sample_offset=sample_offset))


def analysis_plan(name="audio.wav"):
    """Human-reviewed sandbox follow-ups for modes not proved by the pure decoder."""
    return [
        {"rank": 100, "engine": "stego_tools.multimon", "input": name,
         "modes": ["DTMF", "AFSK1200", "AFSK2400", "POCSAG512", "POCSAG1200", "POCSAG2400"],
         "network": "none", "sent": False},
        {"rank": 95, "engine": "stego_tools.minimodem", "input": name,
         "baud_candidates": [300, 1200, 2400, "rtty"], "network": "none", "sent": False},
        {"rank": 90, "engine": "stego_tools.sstv_decode", "input": name,
         "network": "none", "sent": False},
        {"rank": 85, "engine": "stego_tools.spectrogram_text", "input": name,
         "network": "none", "sent": False},
    ]


class _Parser(argparse.ArgumentParser):
    def error(self, message): raise SignalError(message)


def main(argv=None) -> int:
    parser = _Parser(description="CRC-gated BFSK/DBPSK decoder for saved PCM WAV")
    parser.add_argument("mode", choices=("bfsk", "dbpsk", "plan")); parser.add_argument("input")
    parser.add_argument("--baud", type=float); parser.add_argument("--mark", type=float)
    parser.add_argument("--space", type=float); parser.add_argument("--carrier", type=float)
    parser.add_argument("--sample-offset", type=int, default=0)
    try:
        args = parser.parse_args(argv)
        if args.mode == "plan": result = {"plan": analysis_plan(Path(args.input).name)}
        else:
            raw = Path(args.input).read_bytes()
            if args.baud is None: raise SignalError("decoder requires --baud")
            if args.mode == "bfsk":
                if args.mark is None or args.space is None: raise SignalError("BFSK requires --mark/--space")
                payload = decode_bfsk(raw, baud=args.baud, mark_hz=args.mark,
                                      space_hz=args.space, sample_offset=args.sample_offset)
            else:
                if args.carrier is None: raise SignalError("DBPSK requires --carrier")
                payload = decode_dbpsk(raw, baud=args.baud, carrier_hz=args.carrier,
                                       sample_offset=args.sample_offset)
            result = {"mode": args.mode, "verified": payload is not None,
                      "payload_hex": payload.hex() if payload is not None else None,
                      "note": "payload emitted only after C5TG length+CRC verification"}
        print(json.dumps(result, indent=2)); return 0
    except (OSError, SignalError, ValueError, TypeError, OverflowError, MemoryError) as exc:
        print(f"signal_stego: {exc}", file=sys.stderr); return 2


if __name__ == "__main__": raise SystemExit(main())
