"""Independent synthesized SSTV/LoRa vectors and public-boundary fuzz."""
from __future__ import annotations

import json
import math
import random

import numpy as np
import pytest

import rf2_lora_phy as lora
import rf2_sstv_modes as sstv
import signal_stego_depth as audio_base


RATE = 48_000


class _ToneWriter:
    """Phase-continuous N7CXI timing synthesizer, independent of the engine."""

    def __init__(self):
        self.phase = 0.0
        self.elapsed_ms = 0.0
        self.sample_count = 0
        self.parts: list[np.ndarray] = []

    def tone(self, frequency: float, duration_ms: float) -> None:
        target_ms = self.elapsed_ms + duration_ms
        target = int(round(target_ms * RATE / 1000.0))
        count = target - self.sample_count
        positions = np.arange(count, dtype=np.float64)
        angles = self.phase + 2.0 * np.pi * frequency * positions / RATE
        self.parts.append(0.7 * np.sin(angles))
        self.phase = (self.phase + 2.0 * np.pi * frequency * count / RATE) % (2.0 * np.pi)
        self.elapsed_ms = target_ms
        self.sample_count = target

    def video(self, value: int, duration_ms: float) -> None:
        self.tone(1500.0 + value * 800.0 / 255.0, duration_ms)

    def finish(self) -> np.ndarray:
        return np.concatenate(self.parts)


def _sstv_header(writer: _ToneWriter, vis: int) -> None:
    # Dayton proposal: leader, break, leader, start, 7 LSB-first VIS bits,
    # even parity, and stop. A zero is 1300 Hz and a one is 1100 Hz.
    writer.tone(1900, 300)
    writer.tone(1200, 10)
    writer.tone(1900, 300)
    writer.tone(1200, 30)
    bits = [(vis >> index) & 1 for index in range(7)]
    bits.append(sum(bits) & 1)
    for bit in bits:
        writer.tone(1100 if bit else 1300, 30)
    writer.tone(1200, 30)


def _scottie_s2_line() -> tuple[np.ndarray, np.ndarray]:
    red, green, blue = 201, 47, 129
    writer = _ToneWriter()
    _sstv_header(writer, 56)
    writer.tone(1200, 9)
    writer.tone(1500, 1.5)
    writer.video(green, 88.064)
    writer.tone(1500, 1.5)
    writer.video(blue, 88.064)
    writer.tone(1200, 9)
    writer.tone(1500, 1.5)
    writer.video(red, 88.064)
    expected = np.tile(np.array((red, green, blue), dtype=np.uint8), (320, 1))
    return writer.finish(), expected


def _lora_whitening(length: int) -> bytes:
    state = 0xFF
    output = bytearray()
    for _ in range(length):
        output.append(state)
        feedback = ((state >> 7) ^ (state >> 5) ^ (state >> 4) ^ (state >> 3)) & 1
        state = ((state << 1) & 0xFF) | feedback
    return bytes(output)


def _lora_crc(payload: bytes) -> int:
    crc = 0
    for original in payload[:-2]:
        byte = original
        for _ in range(8):
            if ((crc & 0x8000) >> 8) ^ (byte & 0x80):
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
            byte = (byte << 1) & 0xFF
    return (crc ^ payload[-1] ^ (payload[-2] << 8)) & 0xFFFF


def _lora_header(length: int, coding_rate: int, has_crc: bool) -> list[int]:
    high, low = length >> 4, length & 15
    flags = coding_rate << 1 | int(has_crc)
    bit = lambda value, index: (value >> index) & 1
    c4 = bit(high, 3) ^ bit(high, 2) ^ bit(high, 1) ^ bit(high, 0)
    c3 = bit(high, 3) ^ bit(low, 3) ^ bit(low, 2) ^ bit(low, 1) ^ bit(flags, 0)
    c2 = bit(high, 2) ^ bit(low, 3) ^ bit(low, 0) ^ bit(flags, 3) ^ bit(flags, 1)
    c1 = (bit(high, 1) ^ bit(low, 2) ^ bit(low, 0) ^ bit(flags, 2)
          ^ bit(flags, 1) ^ bit(flags, 0))
    c0 = (bit(high, 0) ^ bit(low, 1) ^ bit(flags, 3) ^ bit(flags, 2)
          ^ bit(flags, 1) ^ bit(flags, 0))
    return [high, low, flags, c4, c3 << 3 | c2 << 2 | c1 << 1 | c0]


def _hamming(nibble: int, coding_rate: int) -> int:
    d0, d1, d2, d3 = ((nibble >> index) & 1 for index in range(4))
    if coding_rate == 1:
        parity = d0 ^ d1 ^ d2 ^ d3
        return d0 << 4 | d1 << 3 | d2 << 2 | d3 << 1 | parity
    p0, p1 = d0 ^ d1 ^ d2, d1 ^ d2 ^ d3
    p2, p3 = d0 ^ d1 ^ d3, d0 ^ d2 ^ d3
    full = (d0 << 7 | d1 << 6 | d2 << 5 | d3 << 4
            | p0 << 3 | p1 << 2 | p2 << 1 | p3)
    return full >> (4 - coding_rate)


def _bit_list(value: int, width: int) -> list[int]:
    return [(value >> (width - index - 1)) & 1 for index in range(width)]


def _integer(bits: list[int]) -> int:
    result = 0
    for bit in bits:
        result = result << 1 | bit
    return result


def _inverse_gray(gray: int) -> int:
    result = 0
    while gray:
        result ^= gray
        gray >>= 1
    return result


def _interleave(codewords: list[int], sf: int, coding_rate: int,
                *, reduced: bool) -> list[int]:
    effective_sf = sf - 2 if reduced else sf
    width = coding_rate + 4
    assert len(codewords) == effective_sf
    matrix = [_bit_list(codeword, width) for codeword in codewords]
    output = []
    for row in range(width):
        data_bits = [matrix[(row - column - 1) % effective_sf][row]
                     for column in range(effective_sf)]
        mapped_bits = data_bits + [sum(data_bits) & 1, 0] if reduced else data_bits
        mapped = _integer(mapped_bits)
        output.append((_inverse_gray(mapped) + 1) % (1 << sf))
    return output


def _lora_symbols(payload: bytes, sf: int = 7, coding_rate: int = 2) -> list[int]:
    whitened = bytes(value ^ _lora_whitening(len(payload))[index]
                     for index, value in enumerate(payload))
    body = []
    for byte in whitened:
        body.extend((byte & 15, byte >> 4))
    crc = _lora_crc(payload)
    body.extend((crc >> shift) & 15 for shift in (0, 4, 8, 12))
    nibbles = _lora_header(len(payload), coding_rate, True) + body

    first_count = sf - 2
    first = nibbles[:first_count] + [0] * max(0, first_count - len(nibbles))
    symbols = _interleave([_hamming(value, 4) for value in first], sf, 4, reduced=True)
    remaining = nibbles[first_count:]
    for start in range(0, len(remaining), sf):
        block = remaining[start:start + sf]
        block += [0] * (sf - len(block))
        symbols.extend(_interleave([_hamming(value, coding_rate) for value in block],
                                   sf, coding_rate, reduced=False))
    return symbols


def _lora_iq(symbols: list[int], sf: int) -> np.ndarray:
    chips = 1 << sf
    index = np.arange(chips, dtype=np.float64)
    upchirp = np.exp(2j * np.pi * (index * index / (2.0 * chips) - index / 2.0))
    return np.concatenate([
        upchirp * np.exp(2j * np.pi * symbol * index / chips)
        for symbol in symbols
    ]).astype(np.complex128)


def _accept_or_declared(function, error, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except error as exc:
        assert type(exc) is error
        return None
    except BaseException as exc:  # pragma: no cover - contract assertion
        pytest.fail(f"{function.__name__} leaked {type(exc).__name__}: {exc}")


def test_sstv_phase_continuous_scottie_image_exact_recovery_and_value_objects():
    samples, expected = _scottie_s2_line()
    frame = sstv.decode_sstv(samples, sample_rate=RATE, expected_mode="Scottie S2",
                             max_lines=1)
    spec = sstv.mode_spec(56)
    assert spec == sstv.mode_spec("scottie-s2")
    assert spec.as_dict() == {
        "name": "Scottie S2", "vis": 56, "family": "scottie",
        "width": 320, "height": 256, "scan_ms": 88.064,
    }
    np.testing.assert_array_equal(frame.pixels[0], expected)
    assert frame.as_dict() == {
        "mode": "Scottie S2", "vis": 56, "width": 320, "height": 1,
        "sample_rate": RATE, "complete": False,
    }
    assert frame.ppm() == b"P6\n320 1\n255\n" + expected.tobytes()


def test_lora_independent_tx_symbols_and_numpy_iq_recover_exact_payload():
    payload = b"CSCTF{r3rf}"
    symbols = _lora_symbols(payload, sf=7, coding_rate=2)
    assert lora.whitening_sequence(16).hex() == "fffefcf8f0e1c2850b172f5ebc78f1e3"
    assert lora.whitening_sequence(len(payload)) == _lora_whitening(len(payload))
    assert lora.payload_crc(b"123456789") == _lora_crc(b"123456789") == 0xBEEF
    header = _lora_header(len(payload), 2, True)
    assert lora.header_checksum(len(payload), 2, True) == header[3] << 4 | header[4]

    from_symbols = lora.decode_symbols((value for value in symbols), 7)
    from_iq = lora.decode_iq(_lora_iq(symbols, 7), 7)
    for packet in (from_symbols, from_iq):
        assert packet.payload == payload
        assert packet.coding_rate == 2
        assert packet.crc_received == packet.crc_computed == _lora_crc(payload)
        assert packet.symbols_consumed == len(symbols)
        assert packet.corrected_codewords == 0
        rendered = packet.as_dict()
        assert rendered["payload_ascii"] == "CSCTF{r3rf}"
        assert rendered["crc_ok"] is True
        assert rendered["profile"] == "tapparel-gr-lora-sdr"


def test_sstv_all_public_entrypoints_fail_closed_fuzz_and_oversize(tmp_path, capsys):
    valid, _ = _scottie_s2_line()
    rng = np.random.default_rng(0x53535456)
    bit_flipped = valid.copy()
    bit_view = bit_flipped.view(np.uint64)
    bit_view[len(bit_view) // 2] ^= np.uint64(1)
    corpus = [
        np.array([], dtype=np.float64), np.array([np.nan]),
        np.zeros(512), rng.uniform(-1, 1, 4096), b"\xff" * 4096,
        valid[:100], valid[:-100], bit_flipped,
    ]
    damaged = valid.copy()
    damaged[len(damaged) // 2] = np.nan
    corpus.append(damaged)
    oversized = audio_base.Audio(
        RATE, np.zeros(audio_base.MAX_SAMPLES + 1, dtype=np.int8)
    )
    corpus.append(oversized)
    for source in corpus:
        _accept_or_declared(sstv.decode_sstv, sstv.RF2SSTVError,
                            source, sample_rate=RATE, max_lines=1)
    for value in (None, True, {}, [], "Martin M1", "x" * 1000, -1, 256):
        _accept_or_declared(sstv.mode_spec, sstv.RF2SSTVError, value)
    _accept_or_declared(sstv.decode_sstv, sstv.RF2SSTVError,
                        valid, sample_rate=RATE, max_lines=sstv.MAX_LINES + 1)

    huge = tmp_path / "huge.wav"
    with huge.open("wb") as handle:
        handle.seek(sstv.MAX_FILE)
        handle.write(b"\0")
    assert sstv.main([str(huge)]) == 2
    capsys.readouterr()
    assert sstv.main(["--help"]) == 0
    capsys.readouterr()
    assert sstv.main([]) == 2
    capsys.readouterr()


def test_lora_every_public_entrypoint_fail_closed_fuzz_and_oversize(tmp_path, capsys):
    payload = b"fuzz-vector"
    symbols = _lora_symbols(payload)
    rng = random.Random(0x10A2A)
    streams = [[], symbols[:7], symbols[:-1], symbols + [0],
               [0xFF] * 8,
               [128] * 8, [-1] * 8, rng.choices(range(-32, 160), k=63),
               [0] * (lora.MAX_SYMBOLS + 1)]
    changed = symbols.copy()
    changed[-1] ^= 1
    streams.append(changed)
    for stream in streams:
        _accept_or_declared(lora.decode_symbols, lora.RF2LoRaError, stream, 7)
    for value in (-1, lora.MAX_PAYLOAD + 1, True, None, "1"):
        _accept_or_declared(lora.whitening_sequence, lora.RF2LoRaError, value)
    for value in (b"", b"x", b"x" * (lora.MAX_PAYLOAD + 1), bytearray(b"xx"), None):
        _accept_or_declared(lora.payload_crc, lora.RF2LoRaError, value)
    for args in ((0, 1, True), (1, 0, True), (1, 5, True), (1, 1, 1),
                 (lora.MAX_PAYLOAD + 1, 1, False)):
        _accept_or_declared(lora.header_checksum, lora.RF2LoRaError, *args)

    class OversizedIQ:
        def __len__(self):
            return lora.MAX_IQ_SAMPLES + 1

    iq_values = [[], [complex(float("nan"), 0)] * 128,
                 np.zeros(127, dtype=np.complex128), OversizedIQ()]
    for iq in iq_values:
        _accept_or_declared(lora.decode_iq, lora.RF2LoRaError, iq, 7)

    fixture = tmp_path / "frame.json"
    fixture.write_text(json.dumps({"spreading_factor": 7, "symbols": symbols}), "utf-8")
    assert lora.main([str(fixture)]) == 0
    assert json.loads(capsys.readouterr().out)["payload_hex"] == payload.hex()
    huge = tmp_path / "huge.json"
    with huge.open("wb") as handle:
        handle.seek(lora.MAX_JSON)
        handle.write(b"\0")
    assert lora.main([str(huge)]) == 2
    capsys.readouterr()
    assert lora.main(["--help"]) == 0
    capsys.readouterr()
    assert lora.main([]) == 2
    capsys.readouterr()
