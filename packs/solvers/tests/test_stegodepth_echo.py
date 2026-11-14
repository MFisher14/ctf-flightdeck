"""Non-circular tests for the explicit-delay echo-hiding engine.

The carrier below is synthesized directly from the classic echo model
``y[n] = x[n] + alpha*x[n-delay]``.  It does not call engine code to embed or
serialize the hidden bits.
"""

from __future__ import annotations

import struct

import numpy as np
import pytest

import stegodepth_echo as echo


def _bits_msb(payload: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in payload for shift in range(7, -1, -1)]


def _wav16(channels: list[list[int]], rate: int = 8000, *, junk: bytes = b"") -> bytes:
    """Independent canonical RIFF/WAVE writer used only as the test oracle."""
    count = min(map(len, channels))
    interleaved = [channels[channel][frame]
                   for frame in range(count) for channel in range(len(channels))]
    body = struct.pack(f"<{len(interleaved)}h", *interleaved)
    fmt = struct.pack("<HHIIHH", 1, len(channels), rate,
                      rate * len(channels) * 2, len(channels) * 2, 16)
    chunks = bytearray(b"fmt " + struct.pack("<I", len(fmt)) + fmt)
    if junk:
        chunks += b"JUNK" + struct.pack("<I", len(junk)) + junk
        if len(junk) & 1:
            chunks += b"\x00"
    chunks += b"data" + struct.pack("<I", len(body)) + body
    return b"RIFF" + struct.pack("<I", 4 + len(chunks)) + b"WAVE" + bytes(chunks)


def _echo_carrier(payload: bytes, *, delay_zero: int = 23, delay_one: int = 47,
                  window: int = 1024, alpha: float = 0.72) -> bytes:
    rng = np.random.default_rng(0xC5C7F)
    output: list[int] = []
    for bit in _bits_msb(payload):
        # A fresh, deterministic wideband cover per symbol makes the expected
        # non-selected-delay correlation zero. The embed itself is a direct
        # convolution-like delayed copy, independent of the extractor.
        cover = rng.integers(-9000, 9001, size=window, dtype=np.int32)
        delay = delay_one if bit else delay_zero
        encoded = cover.astype(np.float64)
        encoded[delay:] += alpha * cover[:-delay]
        encoded = np.clip(np.rint(encoded), -32768, 32767).astype(np.int16)
        output.extend(int(value) for value in encoded)
    return _wav16([output], junk=b"odd")


def test_classic_echo_reference_recovers_flag_bytes():
    payload = b"CSCTF{echo_depth}"
    carrier = _echo_carrier(payload)
    result = echo.extract_echo(
        carrier,
        delay_zero=23,
        delay_one=47,
        window_samples=1024,
        max_bits=len(payload) * 8,
        min_margin=0.08,
    )
    assert result is not None
    assert result.payload_msb == payload
    assert result.bits == tuple(_bits_msb(payload))
    assert result.confident >= len(result.bits) * 0.95
    assert result.median_margin > 0.2
    assert all(-1.0 <= score <= 1.0 for pair in result.scores for score in pair)


def test_channel_and_offset_are_explicit_not_guessed():
    payload = b"CSCTF{R}"
    mono = echo.parse_pcm_wav(_echo_carrier(payload))
    assert mono is not None
    values = list(struct.unpack(f"<{mono.frames}h", mono.samples))
    rng = np.random.default_rng(2026)
    decoy = [int(v) for v in rng.integers(-10000, 10001, size=len(values))]
    stereo = _wav16([decoy, values])
    result = echo.extract_echo(
        stereo, delay_zero=23, delay_one=47, window_samples=1024,
        channel=1, max_bits=len(payload) * 8,
    )
    assert result is not None and result.payload_msb == payload
    assert echo.extract_echo(
        stereo, delay_zero=23, delay_one=47, window_samples=1024,
        channel=2, max_bits=8,
    ) is None


def test_pcm_parser_fails_closed_on_truncation_and_inconsistent_fields():
    good = _echo_carrier(b"A")
    assert echo.parse_pcm_wav(good) is not None
    for cut in (0, 1, 4, 8, 11, 12, 19, len(good) - 1):
        assert echo.parse_pcm_wav(good[:cut]) is None
    bad_align = bytearray(good)
    fmt = good.index(b"fmt ") + 8
    struct.pack_into("<H", bad_align, fmt + 12, 4)
    assert echo.parse_pcm_wav(bytes(bad_align)) is None
    assert echo.parse_pcm_wav(b"not wave") is None
    assert echo.parse_pcm_wav(object()) is None


def test_parameter_and_bit_errors_use_only_declared_exception():
    carrier = _echo_carrier(b"A")
    bad_calls = (
        dict(delay_zero=0, delay_one=47, window_samples=1024),
        dict(delay_zero=23, delay_one=23, window_samples=1024),
        dict(delay_zero=23, delay_one=47, window_samples=47),
        dict(delay_zero=23, delay_one=47, window_samples=1024, max_bits=0),
        dict(delay_zero=23, delay_one=47, window_samples=1024, min_margin=float("nan")),
    )
    for kwargs in bad_calls:
        with pytest.raises(echo.StegodepthEchoError):
            echo.extract_echo(carrier, **kwargs)
    with pytest.raises(echo.StegodepthEchoError):
        echo.pack_bits([0, 1, 2])


def test_adversarial_builtin_subclasses_fail_closed():
    class BadBytes(bytes):
        def __len__(self):
            raise RuntimeError("hostile length")

    class BadInt(int):
        def __ge__(self, other):
            raise IndexError("hostile comparison")

    assert echo.parse_pcm_wav(BadBytes(b"RIFF")) is None
    with pytest.raises(echo.StegodepthEchoError):
        echo.extract_echo(
            _echo_carrier(b"A"), delay_zero=BadInt(23),
            delay_one=47, window_samples=1024,
        )


def test_cli_is_guarded_and_reports_candidate(tmp_path, capsys):
    path = tmp_path / "echo.wav"
    path.write_bytes(_echo_carrier(b"CSCTF{cli}"))
    code = echo.main([
        str(path), "--delay-zero", "23", "--delay-one", "47",
        "--window-samples", "1024", "--max-bits", str(10 * 8),
    ])
    report = capsys.readouterr().out
    assert code == 0
    assert '"verified": false' in report
    assert "43534354467b636c697d" in report
    assert echo.main(["--help"]) == 0
    capsys.readouterr()
    assert echo.main([]) == 2

