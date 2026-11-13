"""Independent vector locks for the bounded LoRa PHY artifact decoder.

The transmitter helpers below are a small, test-only transcription of the
published Tapparel gr-lora_sdr TX pipeline.  They deliberately do not import
or call any encoder/helper from rf2_lora_phy (the engine has no encoder):

* header_impl.cc -- explicit-header checksum equations;
* whitening_impl.cc/tables.h -- payload-only x^8+x^6+x^5+x^4+1 sequence;
* add_crc_impl.cc -- LoRa payload CRC construction;
* hamming_enc_impl.cc and interleaver_impl.cc -- coding/interleaving;
* gray_demap_impl.cc -- inverse Gray mapping and the one-bin offset.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Callable

import numpy as np
import pytest

import rf2_lora_phy as lora


def _ref_whitening(length: int) -> bytes:
    state = 0xFF
    result = bytearray()
    for _ in range(length):
        result.append(state)
        new_bit = ((state >> 7) ^ (state >> 5) ^ (state >> 4) ^ (state >> 3)) & 1
        state = ((state << 1) & 0xFF) | new_bit
    return bytes(result)


def _ref_payload_crc(payload: bytes) -> int:
    assert len(payload) >= 2
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


def _ref_header(length: int, coding_rate: int, has_crc: bool) -> list[int]:
    high, low = length >> 4, length & 0x0F
    flags = (coding_rate << 1) | int(has_crc)
    bit = lambda value, index: (value >> index) & 1
    c4 = bit(high, 3) ^ bit(high, 2) ^ bit(high, 1) ^ bit(high, 0)
    c3 = bit(high, 3) ^ bit(low, 3) ^ bit(low, 2) ^ bit(low, 1) ^ bit(flags, 0)
    c2 = bit(high, 2) ^ bit(low, 3) ^ bit(low, 0) ^ bit(flags, 3) ^ bit(flags, 1)
    c1 = (bit(high, 1) ^ bit(low, 2) ^ bit(low, 0) ^ bit(flags, 2) ^
          bit(flags, 1) ^ bit(flags, 0))
    c0 = (bit(high, 0) ^ bit(low, 1) ^ bit(flags, 3) ^ bit(flags, 2) ^
          bit(flags, 1) ^ bit(flags, 0))
    return [high, low, flags, c4, (c3 << 3) | (c2 << 2) | (c1 << 1) | c0]


def _ref_hamming(nibble: int, coding_rate: int) -> int:
    # hamming_enc_impl emits the four data bits least-significant first.
    d0, d1, d2, d3 = ((nibble >> index) & 1 for index in range(4))
    if coding_rate == 1:
        return ((d0 << 4) | (d1 << 3) | (d2 << 2) | (d3 << 1) |
                (d0 ^ d1 ^ d2 ^ d3))
    p0 = d0 ^ d1 ^ d2
    p1 = d1 ^ d2 ^ d3
    p2 = d0 ^ d1 ^ d3
    p3 = d0 ^ d2 ^ d3
    full = ((d0 << 7) | (d1 << 6) | (d2 << 5) | (d3 << 4) |
            (p0 << 3) | (p1 << 2) | (p2 << 1) | p3)
    return full >> (4 - coding_rate)


def _bits(value: int, width: int) -> list[int]:
    return [(value >> (width - index - 1)) & 1 for index in range(width)]


def _integer(bits: list[int]) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def _inverse_gray(gray: int) -> int:
    binary = 0
    while gray:
        binary ^= gray
        gray >>= 1
    return binary


def _ref_interleave(codewords: list[int], sf: int, coding_rate: int,
                    *, reduced: bool) -> list[int]:
    sf_app = sf - 2 if reduced else sf
    assert len(codewords) == sf_app
    width = coding_rate + 4
    matrix = [_bits(codeword, width) for codeword in codewords]
    output = []
    for row in range(width):
        data_bits = [matrix[(row - column - 1) % sf_app][row]
                     for column in range(sf_app)]
        # Tapparel appends parity and zero in the two unused reduced-rate bits.
        mapped_bits = data_bits + [sum(data_bits) & 1, 0] if reduced else data_bits
        mapped = _integer(mapped_bits)
        output.append((_inverse_gray(mapped) + 1) % (1 << sf))
    return output


def _ref_frame(payload: bytes, sf: int, coding_rate: int, *, implicit: bool,
               has_crc: bool, ldro: bool, wrong_header: bool = False,
               wrong_crc: bool = False) -> list[int]:
    whitening = _ref_whitening(len(payload))
    whitened = bytes(byte ^ whitening[index] for index, byte in enumerate(payload))
    body: list[int] = []
    for byte in whitened:
        body.extend((byte & 0x0F, byte >> 4))
    if has_crc:
        crc = _ref_payload_crc(payload) ^ int(wrong_crc)
        body.extend((crc >> shift) & 0x0F for shift in (0, 4, 8, 12))

    if implicit:
        nibbles = body
    else:
        header = _ref_header(len(payload), coding_rate, has_crc)
        if wrong_header:
            header[4] ^= 1
        nibbles = header + body

    first_count = sf - 2
    first = nibbles[:first_count] + [0] * max(0, first_count - len(nibbles))
    symbols = _ref_interleave(
        [_ref_hamming(nibble, 4) for nibble in first], sf, 4, reduced=True
    )
    remaining = nibbles[first_count:]
    block_count = sf - 2 if ldro else sf
    for start in range(0, len(remaining), block_count):
        block = remaining[start:start + block_count]
        block += [0] * (block_count - len(block))
        symbols.extend(_ref_interleave(
            [_ref_hamming(nibble, coding_rate) for nibble in block],
            sf, coding_rate, reduced=ldro,
        ))
    return symbols


def _synthesize_iq(symbols: list[int], sf: int) -> np.ndarray:
    chips = 1 << sf
    index = np.arange(chips, dtype=np.float64)
    base = np.exp(2j * np.pi * (index * index / (2.0 * chips) - index / 2.0))
    blocks = [base * np.exp(2j * np.pi * symbol * index / chips)
              for symbol in symbols]
    return np.concatenate(blocks).astype(np.complex128)


def _raw_for_mapped(mapped: int, sf: int) -> int:
    return (_inverse_gray(mapped) + 1) % (1 << sf)


def _flip_one_interleaver_bit(raw: int, sf: int, mapped_mask: int) -> int:
    shifted = (raw - 1) % (1 << sf)
    mapped = shifted ^ (shifted >> 1)
    return _raw_for_mapped(mapped ^ mapped_mask, sf)


def _accept_or_declared_error(call: Callable[[], object]) -> None:
    try:
        call()
    except lora.RF2LoRaError:
        pass


def test_published_whitening_crc_and_header_vectors() -> None:
    # First sixteen bytes of gr-lora_sdr's published whitening_seq table.
    assert lora.whitening_sequence(16).hex() == "fffefcf8f0e1c2850b172f5ebc78f1e3"
    assert lora.whitening_sequence(37) == _ref_whitening(37)

    # Direct application of add_crc_impl.cc to this conventional test message.
    assert _ref_payload_crc(b"123456789") == 0xBEEF
    assert lora.payload_crc(b"123456789") == 0xBEEF

    assert _ref_header(11, 1, True) == [0, 11, 3, 0, 15]
    assert lora.header_checksum(11, 1, True) == 0x0F
    assert lora.header_checksum(42, 3, True) == 0x18


def test_explicit_cr1_frame_recovers_exact_payload_from_synthetic_iq() -> None:
    payload = b"CSCTF{LoRa}"
    sf, coding_rate = 7, 1
    symbols = _ref_frame(payload, sf, coding_rate, implicit=False,
                         has_crc=True, ldro=False)
    packet = lora.decode_iq(_synthesize_iq(symbols, sf), sf)

    assert packet.payload == payload
    assert packet.spreading_factor == sf
    assert packet.coding_rate == coding_rate
    assert packet.crc_present is True
    assert packet.crc_received == packet.crc_computed == _ref_payload_crc(payload)
    assert packet.header_checksum == 0x0F
    assert packet.symbols_consumed == len(symbols)
    assert packet.corrected_codewords == 0


def test_implicit_cr4_ldro_frame_recovers_exact_payload_from_synthetic_iq() -> None:
    payload = b"LDRO-OK!"
    sf, coding_rate = 8, 4
    symbols = _ref_frame(payload, sf, coding_rate, implicit=True,
                         has_crc=True, ldro=True)
    packet = lora.decode_iq(
        _synthesize_iq(symbols, sf), sf,
        implicit=True, payload_length=len(payload), coding_rate=coding_rate,
        crc_present=True, ldro=True,
    )

    assert packet.payload == payload
    assert packet.coding_rate == coding_rate
    assert packet.implicit_header is True
    assert packet.low_data_rate_optimization is True
    assert packet.crc_received == packet.crc_computed == _ref_payload_crc(payload)
    assert packet.symbols_consumed == len(symbols)


def test_explicit_cr2_without_crc_and_cr3_single_bit_correction() -> None:
    no_crc_payload = b"plain"
    no_crc_symbols = _ref_frame(no_crc_payload, 10, 2, implicit=False,
                                has_crc=False, ldro=False)
    packet = lora.decode_symbols(no_crc_symbols, 10)
    assert packet.payload == no_crc_payload
    assert packet.coding_rate == 2
    assert packet.crc_present is False
    assert packet.crc_received is packet.crc_computed is None

    corrected_payload = b"one corrected codeword"
    corrected = _ref_frame(corrected_payload, 7, 3, implicit=False,
                           has_crc=True, ldro=False)
    # Symbol eight is in the first payload block.  Flipping one mapped matrix
    # bit changes exactly one CR=3 Hamming codeword bit.
    corrected[8] = _flip_one_interleaver_bit(corrected[8], 7, 1 << 6)
    repaired = lora.decode_symbols(corrected, 7)
    assert repaired.payload == corrected_payload
    assert repaired.corrected_codewords == 1


def test_header_checksum_payload_crc_truncation_and_trailing_are_rejected() -> None:
    payload = b"integrity"
    header_bad = _ref_frame(payload, 7, 4, implicit=False, has_crc=True,
                            ldro=False, wrong_header=True)
    with pytest.raises(lora.RF2LoRaError, match="header checksum"):
        lora.decode_symbols(header_bad, 7)

    crc_bad = _ref_frame(payload, 7, 4, implicit=False, has_crc=True,
                         ldro=False, wrong_crc=True)
    with pytest.raises(lora.RF2LoRaError, match="payload CRC"):
        lora.decode_symbols(crc_bad, 7)

    valid = _ref_frame(payload, 7, 4, implicit=False, has_crc=True, ldro=False)
    with pytest.raises(lora.RF2LoRaError, match="truncated"):
        lora.decode_symbols(valid[:-1], 7)
    with pytest.raises(lora.RF2LoRaError, match="unexpected symbols"):
        lora.decode_symbols(valid + [0], 7)
    assert lora.decode_symbols(valid + [0], 7, allow_trailing=True).payload == payload


def test_fail_closed_for_empty_random_malformed_and_oversized_inputs() -> None:
    malformed: list[Callable[[], object]] = [
        lambda: lora.decode_symbols([], 7),
        lambda: lora.decode_symbols([0] * 7, 7),
        lambda: lora.decode_symbols([128] * 8, 7),
        lambda: lora.decode_symbols([0] * 8, True),
        lambda: lora.decode_symbols([0] * (lora.MAX_SYMBOLS + 1), 7),
        lambda: lora.decode_symbols([0] * 8, 7, implicit=True),
        lambda: lora.decode_iq([], 7),
        lambda: lora.decode_iq([complex(float("nan"), 0)] * 128, 7),
        lambda: lora.whitening_sequence(-1),
        lambda: lora.payload_crc(b""),
        lambda: lora.payload_crc(b"x"),
        lambda: lora.header_checksum(0, 1, True),
        lambda: lora.header_checksum(1, 5, True),
    ]
    for call in malformed:
        with pytest.raises(lora.RF2LoRaError):
            call()

    rng = np.random.default_rng(0xC5C7F)
    for length in (1, 8, 9, 17, 63, 257):
        random_symbols = rng.integers(-32, 160, size=length).tolist()
        _accept_or_declared_error(lambda values=random_symbols: lora.decode_symbols(values, 7))


def test_guarded_cli_decodes_symbols_and_contains_argparse(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    payload = b"CLI-vector"
    symbols = _ref_frame(payload, 7, 2, implicit=False, has_crc=True, ldro=False)
    fixture = tmp_path / "frame.json"
    fixture.write_text(json.dumps({"spreading_factor": 7, "symbols": symbols}), "utf-8")

    assert lora.main([str(fixture)]) == 0
    decoded = json.loads(capsys.readouterr().out)
    assert decoded["payload_hex"] == payload.hex()
    assert decoded["crc_ok"] is True
    assert lora.main(["--help"]) == 0
    capsys.readouterr()
    assert lora.main([]) == 2
    assert "required" in capsys.readouterr().err

