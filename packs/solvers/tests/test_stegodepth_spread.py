"""Independent direct-sequence synthesis for the audio DSSS correlator."""

from __future__ import annotations

import struct

import numpy as np
import pytest

import stegodepth_spread as spread


PN = (1, 1, -1, 1, -1, -1, 1, -1, 1, -1, -1, -1, 1, 1, 1, -1)


def _payload_bits(payload: bytes) -> list[int]:
    return [(value >> shift) & 1 for value in payload for shift in range(7, -1, -1)]


def _wav(samples: list[int], rate: int = 16000) -> bytes:
    body = struct.pack(f"<{len(samples)}h", *samples)
    fmt = struct.pack("<HHIIHH", 1, 1, rate, rate * 2, 2, 16)
    chunks = b"fmt " + struct.pack("<I", len(fmt)) + fmt
    chunks += b"data" + struct.pack("<I", len(body)) + body
    return b"RIFF" + struct.pack("<I", 4 + len(chunks)) + b"WAVE" + chunks


def _carrier(payload: bytes, samples_per_chip: int = 6) -> bytes:
    """Reference additive DSSS embed, written without engine helpers."""
    rng = np.random.default_rng(0xD555)
    output: list[int] = []
    reference = np.repeat(np.asarray(PN, dtype=np.int32), samples_per_chip)
    for bit in _payload_bits(payload):
        cover = rng.integers(-1800, 1801, size=reference.size, dtype=np.int32)
        sign = 1 if bit else -1
        encoded = np.clip(cover + sign * 5200 * reference, -32768, 32767)
        output.extend(int(value) for value in encoded)
    return _wav(output)


def test_explicit_pn_matched_filter_recovers_reference_embed():
    payload = b"CSCTF{dsss}"
    result = spread.extract_dsss(
        _carrier(payload), chips=PN, samples_per_chip=6,
        max_bits=len(payload) * 8, min_correlation=0.8,
    )
    assert result is not None
    assert result.payload_msb == payload
    assert result.bits == tuple(_payload_bits(payload))
    assert result.confident == len(result.bits)
    assert result.median_absolute_correlation > 0.9
    assert all((-1.0 <= value <= 1.0) for value in result.correlations)


def test_chip_text_conventions_are_exact_and_equivalent():
    plus_minus = "".join("+" if chip > 0 else "-" for chip in PN)
    binary = ",".join("1" if chip > 0 else "0" for chip in PN)
    assert spread.parse_chips(plus_minus) == PN
    assert spread.parse_chips(binary) == PN
    assert spread.parse_chips([1 if chip > 0 else 0 for chip in PN]) == PN


def test_malformed_audio_declines_and_parameter_errors_are_declared():
    assert spread.extract_dsss(
        b"not a wave", chips=PN, samples_per_chip=6,
    ) is None
    with pytest.raises(spread.StegodepthSpreadError):
        spread.parse_chips("++++")
    with pytest.raises(spread.StegodepthSpreadError):
        spread.parse_chips("+-x-")
    with pytest.raises(spread.StegodepthSpreadError):
        spread.extract_dsss(_carrier(b"A"), chips=PN, samples_per_chip=0)
    with pytest.raises(spread.StegodepthSpreadError):
        spread.extract_dsss(
            _carrier(b"A"), chips=PN, samples_per_chip=6,
            min_correlation=float("inf"),
        )


def test_parameter_text_and_symbol_resource_caps_are_declared(monkeypatch):
    class BadInt(int):
        def __ge__(self, other):
            raise IndexError("hostile comparison")

    with pytest.raises(spread.StegodepthSpreadError):
        spread.extract_dsss(
            _carrier(b"A"), chips=PN, samples_per_chip=BadInt(6),
        )
    with pytest.raises(spread.StegodepthSpreadError, match="text exceeds"):
        spread.parse_chips(" " * (spread.MAX_CHIP_TEXT + 1))
    monkeypatch.setattr(spread, "MAX_SYMBOL_SAMPLES", 32)
    with pytest.raises(spread.StegodepthSpreadError, match="symbol exceeds"):
        spread.extract_dsss(_carrier(b"A"), chips=PN, samples_per_chip=6)


def test_partial_symbol_and_wrong_channel_fail_closed():
    carrier = _carrier(b"A")
    assert spread.extract_dsss(
        carrier[:44], chips=PN, samples_per_chip=6,
    ) is None
    assert spread.extract_dsss(
        carrier, chips=PN, samples_per_chip=6, channel=1,
    ) is None


def test_cli_is_guarded_and_labels_output_unverified(tmp_path, capsys):
    payload = b"CSCTF{cli}"
    path = tmp_path / "spread.wav"
    path.write_bytes(_carrier(payload))
    chips = "".join("+" if chip > 0 else "-" for chip in PN)
    code = spread.main([
        str(path), "--chips", chips, "--samples-per-chip", "6",
        "--max-bits", str(len(payload) * 8),
    ])
    output = capsys.readouterr().out
    assert code == 0
    assert '"verified": false' in output
    assert payload.hex() in output
    assert spread.main(["--help"]) == 0
    capsys.readouterr()
    assert spread.main([]) == 2

