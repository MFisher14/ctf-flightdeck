"""Independent sampled-sinusoid and PCM fixtures for audio_tones.

Oracles: f(t)=sin(2*pi*f*t), explicit frequency/code affine mapping, ordinary
channel arithmetic, and Python wave / SoundFile format semantics:
https://docs.python.org/3/library/wave.html
https://python-soundfile.readthedocs.io/en/latest/
No engine output is used to construct an expected value.
"""
import io
import json
import random
import wave

import numpy as np
import pytest

import audio_tones as engine


RATE = 16000


def wav_bytes(samples, rate=RATE, channels=1):
    buffer = io.BytesIO()
    with wave.open(buffer, 'wb') as writer:
        writer.setparams((channels, 2, rate, 0, 'NONE', 'not compressed'))
        writer.writeframes(np.asarray(samples, dtype='<i2').tobytes())
    return buffer.getvalue()


def tone(hz, seconds=0.2):
    return 0.5 * np.sin(2 * np.pi * hz * np.arange(round(RATE * seconds)) / RATE)


def test_pcm_channel_average_and_normalization(tmp_path):
    path = tmp_path / 'stereo.wav'
    path.write_bytes(wav_bytes([[1000, 3000], [-2000, 0], [4000, 4000]], channels=2))
    samples, rate = engine.load_audio(path)
    np.testing.assert_allclose(samples, [0.5, -0.25, 1.0], atol=1e-12)
    assert rate == RATE


@pytest.mark.parametrize('hz', [125, 440, 697, 1209, 3200])
def test_peak_frequency_against_analytic_sinusoid(hz):
    assert engine.peak_freq(tone(hz), RATE) == pytest.approx(hz, abs=0.6)


def test_exact_linear_symbol_recovery_and_cli(tmp_path, capsys):
    expected = 'CSCTF{RF_123}'
    samples = np.concatenate([tone(200 + 20 * ord(c)) for c in expected])
    path = tmp_path / 'linear.wav'
    path.write_bytes(wav_bytes(np.rint(samples * 30000)))
    result = engine.decode(path, block_ms=200, mode='linear', base=200, step=20)
    assert result['codes'] == list(expected.encode())
    assert result['candidates'] == [('linear', expected)]
    assert engine.find_flags(result) == [expected]
    assert expected in engine.report(result)
    assert engine.main([str(path), '--block-ms', '200', '--base', '200', '--step', '20', '--json']) == 0
    assert json.loads(capsys.readouterr().out)['codes'] == list(expected.encode())


def test_silence_segmentation_and_cluster_ranks():
    samples = np.concatenate([np.zeros(800), tone(600, 0.1), np.zeros(800), tone(1200, 0.1), np.zeros(800)])
    assert engine.detect_segments(samples, RATE) == [(800, 2400), (3200, 4800)]
    assert engine.block_freqs(samples, RATE) == pytest.approx([600, 1200], abs=0.1)
    codes, centers = engine.freqs_to_codes_cluster([100, 300, 200, 100, 200], offset=65)
    assert codes == [65, 67, 66, 65, 66]
    assert centers == [100, 200, 300]
    assert engine.codes_to_text(codes) == 'ACBAB'
    assert engine.freqs_to_codes_linear([850, 860, 870], 200, 10) == [65, 66, 67]


def test_independent_two_stream_xor(tmp_path):
    expected = b'CSCTF{x}'
    key = bytes([11, 17, 3, 5, 2, 9, 31, 7])
    cipher = bytes(a ^ b for a, b in zip(expected, key))
    chunks = [np.zeros(800)]
    for stream in (cipher, key):
        for code in stream:
            chunks.extend([tone(300 + 20 * code), np.zeros(800)])
        chunks.append(np.zeros(6400))
    path = tmp_path / 'xor.wav'
    path.write_bytes(wav_bytes(np.rint(np.concatenate(chunks) * 30000)))
    result = engine.decode(path, mode='linear', base=300, step=20, xor=True)
    assert result['n_streams'] == 2
    assert result['streams'][0]['codes'] == list(cipher)
    assert result['streams'][1]['codes'] == list(key)
    assert dict(result['candidates'])['xor(codes)'] == expected.decode()


def test_small_output_cap(tmp_path, monkeypatch):
    path = tmp_path / 'oversized.wav'
    path.write_bytes(wav_bytes(np.arange(100)))
    monkeypatch.setattr(engine, 'MAX_SAMPLES', 16)
    samples, _ = engine.load_audio(path)
    assert len(samples) == 16


def test_sample_cap_is_applied_to_reader_before_allocation(tmp_path, monkeypatch):
    path = tmp_path / 'oversized.wav'
    path.write_bytes(wav_bytes(np.arange(100)))
    monkeypatch.setattr(engine, 'MAX_SAMPLES', 16)
    original = engine.sf.read
    requested = []
    def recording_read(*args, **kwargs):
        requested.append(kwargs.get('frames', -1))
        return original(*args, **kwargs)
    monkeypatch.setattr(engine.sf, 'read', recording_read)
    engine.load_audio(path)
    assert all(0 <= n <= 16 for n in requested)


def test_finite_signal_fuzz_and_partial_blocks():
    rng = np.random.default_rng(0x617564)
    for length in (0, 1, 3, 4, 17, 320, 321, 1000):
        for samples in (np.zeros(length), rng.uniform(-1, 1, length)):
            assert np.isfinite(engine.peak_freq(samples, RATE))
            for segments in (engine.detect_segments(samples, RATE),
                             engine.detect_segments(samples, RATE, block_ms=20),
                             engine.split_streams(samples, RATE)):
                assert all(0 <= start < end <= length for start, end in segments)
            assert all(np.isfinite(f) for f in engine.block_freqs(samples, RATE))
    assert engine.detect_segments(np.ones(800), RATE, block_ms=20) == [(0, 320), (320, 640), (640, 800)]


@pytest.mark.parametrize('entrypoint', [engine.load_audio, engine.decode])
@pytest.mark.parametrize('raw', [b'', b'\xff' * 64, random.Random(51).randbytes(64), b'RIFF\xff\xff\xff\xffWAVEfmt '])
def test_malformed_audio_must_fail_closed(entrypoint, raw, tmp_path):
    path = tmp_path / 'bad.wav'
    path.write_bytes(raw)
    entrypoint(path)


def test_bitflipped_pcm_and_truncated_valid_payload_are_bounded(tmp_path):
    valid = bytearray(wav_bytes(np.arange(1000)))
    rng = random.Random(13)
    for _ in range(16):
        raw = bytearray(valid)
        raw[rng.randrange(44, len(raw))] ^= 1 << rng.randrange(8)
        path = tmp_path / 'mutant.wav'
        path.write_bytes(raw)
        samples, _ = engine.load_audio(path)
        assert len(samples) <= 1000
    path.write_bytes(valid[:-12])
    samples, _ = engine.load_audio(path)
    assert len(samples) <= 1000


@pytest.mark.parametrize('call', [
    lambda: engine.freqs_to_codes_linear([float('nan')], 0, 1),
    lambda: engine.freqs_to_codes_linear([float('inf')], 0, 1),
    lambda: engine.detect_segments(np.ones(4), RATE, block_ms=float('inf')),
])
def test_nonfinite_input_must_fail_closed(call):
    call()


@pytest.mark.parametrize('argv', [[], ['--help'], ['--unknown']])
def test_cli_parse_errors_are_guarded(argv):
    assert isinstance(engine.main(argv), int)
