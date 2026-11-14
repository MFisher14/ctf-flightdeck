from __future__ import annotations

import math
import random
import sys
from io import BytesIO
from pathlib import Path

import pytest


TK = Path(__file__).resolve().parents[1] / "solvers" / "toolkits"
sys.path.insert(0, str(TK))
import audio_stego as A  # noqa: E402
import signal_stego as S  # noqa: E402
import transform_stego as T  # noqa: E402


PAYLOAD = b"CSCTF{verified}"


def _matrix(n=128):
    return [[96 + ((x * 17 + y * 31) % 64) for x in range(n)] for y in range(n)]


@pytest.mark.parametrize("name,embed,extract", [
    ("dct", lambda m: T.dct_embed(m, PAYLOAD), T.dct_extract),
    ("dwt", lambda m: T.dwt_embed(m, PAYLOAD), T.dwt_extract),
    ("spread", lambda m: T.spread_embed(m, PAYLOAD, b"fixture-seed", strength=12),
     lambda m: T.spread_extract(m, b"fixture-seed")),
    ("adaptive", lambda m: T.adaptive_embed(m, PAYLOAD, threshold=16),
     lambda m: T.adaptive_extract(m, threshold=16)),
])
def test_transform_roundtrip_is_crc_verified(name, embed, extract):
    encoded = embed(_matrix())
    assert extract(encoded) == PAYLOAD, name


def test_hamming_matrix_roundtrip_and_corruption_declines():
    carriers = [128] * 20_000
    encoded = T.matrix_embed(carriers, PAYLOAD, k=3)
    assert T.matrix_extract(encoded, k=3) == PAYLOAD
    encoded[0] ^= 1
    assert T.matrix_extract(encoded, k=3) is None
    assert T.spread_extract(T.spread_embed(_matrix(), PAYLOAD, b"right", strength=12), b"wrong") is None


def _wav_bfsk(payload, rate=8000, baud=100, mark=1400, space=900):
    bits = list(T._bits(T.pack_frame(payload)))
    width = rate // baud
    samples = []
    for bit in bits:
        freq = mark if bit else space
        samples.extend(round(12000 * math.sin(2 * math.pi * freq * i / rate)) for i in range(width))
    return A.build_wav(rate, 16, [samples])


def _wav_dbpsk(payload, rate=8000, baud=100, carrier=1000):
    bits = list(T._bits(T.pack_frame(payload)))
    width = rate // baud
    phase, samples = 0.0, []
    # Reference symbol.
    samples.extend(round(12000 * math.sin(2 * math.pi * carrier * i / rate + phase)) for i in range(width))
    for bit in bits:
        if bit: phase += math.pi
        samples.extend(round(12000 * math.sin(2 * math.pi * carrier * i / rate + phase)) for i in range(width))
    return A.build_wav(rate, 16, [samples])


def test_bfsk_and_dbpsk_verified_roundtrips():
    assert S.decode_bfsk(_wav_bfsk(PAYLOAD), baud=100, mark_hz=1400, space_hz=900) == PAYLOAD
    assert S.decode_dbpsk(_wav_dbpsk(PAYLOAD), baud=100, carrier_hz=1000) == PAYLOAD


def test_wrong_parameters_and_unframed_audio_decline():
    wav = _wav_bfsk(PAYLOAD)
    assert S.decode_bfsk(wav, baud=100, mark_hz=1800, space_hz=1700) is None
    blank = A.build_wav(8000, 16, [[0] * 8000])
    assert S.decode_dbpsk(blank, baud=100, carrier_hz=1000) is None
    assert all(row["sent"] is False and row["network"] == "none" for row in S.analysis_plan())


def test_installed_pillow_and_numpy_reference_agreement():
    image = pytest.importorskip("PIL.Image")
    numpy = pytest.importorskip("numpy")
    pgm = b"P5\n4 2\n255\n" + bytes(range(8))
    assert T.read_pgm(pgm) == numpy.asarray(image.open(BytesIO(pgm))).tolist()

    wav = _wav_bfsk(b"x")
    info, channels = A.wav_channels(wav)
    width = info["rate"] // 100
    expected = list(T._bits(T.pack_frame(b"x")))[:16]
    observed = []
    for at in range(16):
        power = abs(numpy.fft.rfft(channels[0][at * width:(at + 1) * width]))
        observed.append(1 if power[14] >= power[9] else 0)
    assert observed == expected


def test_cli_guarded_boundaries(capsys):
    assert T.main([]) == 2
    assert "transform_stego:" in capsys.readouterr().err
    assert S.main([]) == 2
    assert "signal_stego:" in capsys.readouterr().err


def test_pgm_parser_mutation_fuzz_5000_cases():
    rng = random.Random(0x57E60)
    for _ in range(5000):
        blob = rng.randbytes(rng.randrange(0, 300))
        try:
            matrix = T.read_pgm(blob)
            assert len(matrix) * len(matrix[0]) <= T.MAX_PIXELS
        except T.StegoError:
            pass


def test_wav_decoder_mutation_fuzz_5000_cases():
    rng = random.Random(0xA0D10)
    for _ in range(5000):
        blob = rng.randbytes(rng.randrange(0, 260))
        try:
            result = S.decode_bfsk(blob, baud=100, mark_hz=1400, space_hz=900)
            assert result is None or isinstance(result, bytes)
        except S.SignalError:
            pass
