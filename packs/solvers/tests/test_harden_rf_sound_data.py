"""Independent PCM/DTMF/ggwave fixtures for sound_data, without audio playback.

ITU-T Q.23 (1988), Figure 1: the 4x4 frequency matrix used below.
https://www.itu.int/rec/T-REC-Q.23-198811-I/en
ggwave C API specifies I16=4 and F32=5 in ggwave_SampleFormat:
https://github.com/ggerganov/ggwave/blob/master/include/ggwave/ggwave.h
Python wave provides the independent PCM envelope writer.
"""
import io
import random
import sys
import wave

import ggwave
import numpy as np
import pytest
import soundfile as sf

import sound_data as engine


def pcm_wav(raw, width=2, channels=1, rate=16000):
    output = io.BytesIO()
    with wave.open(output, 'wb') as writer:
        writer.setparams((channels, width, rate, 0, 'NONE', 'not compressed'))
        writer.writeframes(raw)
    return output.getvalue()


@pytest.mark.parametrize(('raw', 'width', 'expected'), [
    (bytes([0, 64, 128, 192, 255]), 1, [-32768, -16384, 0, 16384, 32512]),
    (np.array([-32768, -1, 0, 1, 32767], dtype='<i2').tobytes(), 2, [-32768, -1, 0, 1, 32767]),
    (b'\0\0\x80\0\0\0\xff\xff\x7f', 3, [-32767, 0, 32766]),
    (np.array([-2147483648, 0, 2147483647], dtype='<i4').tobytes(), 4, [-32767, 0, 32766]),
])
def test_pcm_widths_against_exact_integer_scaling(raw, width, expected, tmp_path):
    path = tmp_path / 'pcm.wav'
    path.write_bytes(pcm_wav(raw, width))
    result = engine.load_wav(path)
    assert result.int16().tolist() == expected
    assert result.samplerate == 16000
    assert result.nframes == len(expected)
    assert result.nchannels == 1


def test_stereo_pcm_downmix_preserves_amplitude(tmp_path):
    path = tmp_path / 'stereo.wav'
    path.write_bytes(pcm_wav(np.array([[1000, 3000], [-1000, -3000], [20000, 20000]], dtype='<i2').tobytes(), channels=2))
    assert engine.load_wav(path).int16().tolist() == [2000, -2000, 20000]


def test_float_pcm_fallback_uses_normalized_units(tmp_path):
    path = tmp_path / 'float.wav'
    sf.write(path, np.array([-1, -0.5, 0, 0.5, 1], dtype=np.float32), 16000, subtype='FLOAT')
    assert engine.load_wav(path).int16().tolist() == [-32767, -16384, 0, 16384, 32767]


def test_all_sixteen_itu_q23_dtmf_pairs(tmp_path):
    expected = '123A456B789C*0#D'
    chunks = [np.zeros(1600)]
    t = np.arange(1920) / 16000
    for low in (697, 770, 852, 941):
        for high in (1209, 1336, 1477, 1633):
            chunks.extend([0.35 * (np.sin(2 * np.pi * low * t) + np.sin(2 * np.pi * high * t)), np.zeros(1280)])
    path = tmp_path / 'dtmf.wav'
    path.write_bytes(pcm_wav(np.rint(np.concatenate(chunks) * 30000).astype('<i2').tobytes()))
    result = engine.decode_dtmf(path)
    assert result['keys'] == expected
    assert result['sure'] is True
    assert result['candidates'] == [('dtmf', expected)]


def test_real_ggwave_encoder_with_explicit_i16_waveform(tmp_path):
    expected = b'CSCTF{ggwave_i16}'
    params = ggwave.getDefaultParameters()
    params.update(sampleFormatInp=4, sampleFormatOut=4)
    transmitter = ggwave.init(params)
    receiver = ggwave.init(params)
    try:
        raw = ggwave.encode(expected, protocolId=1, volume=20, instance=transmitter)
        assert ggwave.decode(receiver, raw) == expected  # Independent library proves the fixture.
    finally:
        ggwave.free(transmitter)
        ggwave.free(receiver)
    path = tmp_path / 'ggwave.wav'
    path.write_bytes(pcm_wav(raw, rate=48000))
    assert engine.decode_ggwave(path)['payload'] == expected.decode()


def test_ggwave_absent_is_clean_recipe(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, 'ggwave', None)
    result = engine.decode_ggwave(tmp_path / 'not-read.wav')
    assert result['available'] is False
    assert result['payload'] is None
    assert 'ggwave' in result['recipe']


def test_tone_hub_exact_frequency_mapping(tmp_path):
    expected = 'CSCTF{hub}'
    t = np.arange(3200) / 16000
    samples = np.concatenate([0.5 * np.sin(2 * np.pi * (200 + ord(c) * 20) * t) for c in expected])
    path = tmp_path / 'tones.wav'
    path.write_bytes(pcm_wav(np.rint(samples * 30000).astype('<i2').tobytes()))
    result = engine.decode_tones(path, block_ms=200, mode='linear', base=200, step=20)
    assert result['codes'] == list(expected.encode())
    assert engine.find_flags(result) == [expected]


def test_recursive_flags_and_nonexecuting_morse_recipe(capsys):
    assert engine.find_flags({'a': ['CSCTF{one}', ('CTF{two}', 'CSCTF{one}')], 'n': 4}) == ['CSCTF{one}', 'CTF{two}']
    # This module intentionally has no Morse decoder: it returns a recipe string.
    assert 'multimon-ng -a MORSE_CW' in engine.recipes()
    assert 'tools/sandbox.py' in engine.recipes()
    assert engine.main(['recipes']) == 0
    assert 'MORSE_CW' in capsys.readouterr().out


def test_pcm_read_cap_and_bitflipped_payload(tmp_path, monkeypatch):
    path = tmp_path / 'small-cap.wav'
    raw = bytearray(pcm_wav(np.arange(200, dtype='<i2').tobytes()))
    monkeypatch.setattr(engine, 'MAX_SAMPLES', 16)
    rng = random.Random(41)
    for _ in range(12):
        mutant = bytearray(raw)
        mutant[rng.randrange(44, len(mutant))] ^= 1 << rng.randrange(8)
        path.write_bytes(mutant)
        assert engine.load_wav(path).nframes == 16


def test_float_fallback_reader_cap_before_allocation(tmp_path, monkeypatch):
    path = tmp_path / 'oversized-float.wav'
    sf.write(path, np.zeros(100), 16000, subtype='FLOAT')
    monkeypatch.setattr(engine, 'MAX_SAMPLES', 16)
    original = sf.read
    requested = []
    def recording_read(*args, **kwargs):
        requested.append(kwargs.get('frames', -1))
        return original(*args, **kwargs)
    monkeypatch.setattr(engine.sf, 'read', recording_read)
    assert engine.load_wav(path).nframes == 16
    assert all(0 <= count <= 16 for count in requested)


@pytest.mark.parametrize('raw', [b'', b'\xff' * 64, random.Random(77).randbytes(64), b'RIFF\xff\xff\xff\xffWAVEfmt '])
def test_hub_and_dtmf_fail_closed_on_bad_files(raw, tmp_path, monkeypatch):
    path = tmp_path / 'bad.wav'
    path.write_bytes(raw)
    monkeypatch.setitem(sys.modules, 'ggwave', None)
    assert isinstance(engine.analyze(path), dict)
    assert engine.decode_dtmf(path)['keys'] is None


@pytest.mark.parametrize('entrypoint', [engine.load_wav, engine.decode_tones, engine.decode_ggwave])
@pytest.mark.parametrize('raw', [b'', b'\xff' * 64, random.Random(77).randbytes(64), b'RIFF\xff\xff\xff\xffWAVEfmt '])
def test_leaf_malformed_files_must_fail_closed(entrypoint, raw, tmp_path):
    path = tmp_path / 'bad.wav'
    path.write_bytes(raw)
    entrypoint(path)


def test_truncated_pcm_sample_must_fail_closed(tmp_path):
    path = tmp_path / 'odd.wav'
    path.write_bytes(pcm_wav(b'\x01\x02\x03\x04')[:-1])
    engine.load_wav(path)


@pytest.mark.parametrize('argv', [['--help'], ['--unknown']])
def test_cli_argument_exit_is_guarded(argv):
    assert isinstance(engine.main(argv), int)
