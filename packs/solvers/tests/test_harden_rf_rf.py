"""RF vectors independently synthesized from documented modulation/NFC semantics.

References: NXP AN1305 (FF0780 transport access), NFC RTD Text/URI via
https://w3c-cg.github.io/web-nfc/ ; Flipper format documentation at
https://developer.flipper.net/flipperformat.html . No live requests in tests.
"""
import io
import random
import struct
import wave

import numpy as np
import pytest

import rf


SUB = (b'Filetype: Flipper SubGhz RAW File\nVersion: 1\nFrequency: 433920000\n'
       b'Preset: FuriHalSubGhzPresetOok650Async\nProtocol: RAW\nRAW_Data: 100 -300 300 -100\n')
NDEF = bytes.fromhex('d1010f5402656e48656c6c6f20576f726c6421')
BAD_WAV = bytes.fromhex('524946462c00000057415645666d74201000040001000100401f0000803e000002001000646174610800000000800000ff7fd204')


def wav_bytes():
    buf = io.BytesIO()
    with wave.open(buf, 'wb') as writer:
        writer.setparams((1, 2, 8000, 0, 'NONE', 'not compressed'))
        writer.writeframes(struct.pack('<hhhh', -32768, 0, 32767, 1234))
    return buf.getvalue()


def test_flipper_metadata_and_bounded_timings(monkeypatch):
    result = rf.sub_info(SUB)
    assert result['frequency'] == 433920000
    assert result['modulation'] == 'ook'
    assert result['timings'] == [100, -300, 300, -100]
    assert rf.flipper_parse(SUB)['kind'] == 'sub'
    monkeypatch.setattr(rf, 'MAX_TIMINGS', 2)
    assert rf.sub_info(SUB)['timings_cut'] is True


def test_synthesized_pwm_manchester_and_ook():
    bits = '1010011000111100'
    pwm = [v for bit in bits for v in ((300, -100) if bit == '1' else (100, -300))]
    assert rf.pwm_bits(pwm, te=100) == bits
    # IEEE Manchester: low->high represents 1. Build durations independently.
    manchester = [v for bit in bits for v in ((-100, 100) if bit == '1' else (100, -100))]
    assert rf.manchester_bits(manchester, te=100)['ieee'] == bits
    assert rf.bits_to_bytes(bits) == b'\xa6\x3c'
    assert rf.bits_to_bytes(bits, msb_first=False) == b'\x65\x3c'
    # Signed I/Q real magnitudes, four samples per known OOK level.
    iq = np.repeat(np.array([0, 20, 0, 20, 0], dtype=np.int8), 4)
    interleaved = np.column_stack((iq, np.zeros(len(iq), dtype=np.int8)))
    out = rf.iq_pulses(interleaved.tobytes(), 'cs8', smooth=1)
    assert out['timings'] == [4, -4, 4, -4]
    assert out['threshold'] == 10


def test_synthesized_afsk_asynchronous_bytes():
    payload = b'CSCTF{fsk}'
    bits = [1] * 12
    for value in payload:
        bits.extend([0] + [(value >> bit) & 1 for bit in range(8)] + [1, 1])
    bits.extend([1] * 12)
    # 300 baud, 48 kHz, Bell103 mark1270/space1070. Continuous phase.
    frequency = np.repeat(np.where(np.array(bits), 1270.0, 1070.0), 160)
    samples = np.sin(2 * np.pi * np.cumsum(frequency) / 48000)
    out = rf.afsk_decode(samples, 48000, 300, 1270, 1070)
    assert out['bytes'] == payload
    assert out['framing_errors'] == 0


def test_ndef_and_mifare_documented_vectors():
    record = rf.ndef_parse(NDEF)[0]
    assert (record['type'], record['lang'], record['text']) == ('T', 'en', 'Hello World!')
    assert rf.ndef_tlv(bytes([3, len(NDEF)]) + NDEF + b'\xfe')[0][0]['text'] == 'Hello World!'
    uri = b'\xd1\x01\x0cU\x04example.com'
    assert rf.ndef_parse(uri)[0]['uri'] == 'https://example.com'
    assert rf.mfc_access(bytes.fromhex('ff0780')) == [(0, 0, 0)] * 3 + [(0, 0, 1)]
    block = struct.pack('<iIiBBBB', -123, (~-123) & 0xffffffff, -123, 4, 251, 4, 251)
    assert rf.mfc_value(block) == {'value': -123, 'address': 4}


def test_em4100_parity_independent_encoder():
    payload = bytes.fromhex('0102030405')
    rows = [f'{value:08b}'[part:part+4] for value in payload for part in (0, 4)]
    frame = '1' * 9 + ''.join(row + str(row.count('1') % 2) for row in rows)
    frame += ''.join(str(sum(int(row[col]) for row in rows) % 2) for col in range(4)) + '0'
    assert rf.em4100_bits(frame) == payload
    assert rf.em4100_bits(frame[17:] + frame[:17]) == payload
    assert rf.em4100_bytes(payload)['id32'] == 0x02030405


def test_nec_known_address_and_command():
    durations = [9000, 4500]
    for value in [0x12, 0xed, 0x34, 0xcb]:
        for bit in range(8):
            durations += [560, 1690 if value & (1 << bit) else 560]
    durations += [560, 40000]
    assert rf.nec_decode(durations) == [{'protocol': 'NEC', 'address': 0x12, 'command': 0x34, 'repeat': False}]


def test_wav_header_pcm_and_explicit_limit():
    data = wav_bytes()
    out = rf.wav_info(data)
    assert (out['frames'], out['sample_rate'], out['bits_per_sample']) == (4, 8000, 16)
    samples, rate = rf.wav_samples(data, limit=2)
    assert rate == 8000
    np.testing.assert_array_equal(samples, [-32768, 0])


PARSERS = [rf.flipper_parse, rf.sub_info, rf.nfc_info, rf.rfid_info, rf.ir_info,
           rf.mfc_parse, rf.ndef_tlv, rf.wav_info, rf.wav_samples,
           rf.ihex_parse, rf.srec_parse, rf.can_parse, rf.logic_csv]


@pytest.mark.parametrize('parser', PARSERS)
def test_byte_parser_deterministic_fuzz(parser):
    rng = random.Random(0x5246)
    inputs = [b'', b'\xff' * 64, b'\0' * 64]
    inputs += [rng.randbytes(n) for n in (1, 4, 15, 32, 128, 1024)]
    for valid in (SUB, NDEF, wav_bytes()):
        inputs += [valid[:n] for n in (1, 4, 12, len(valid) - 1)]
        for _ in range(8):
            damaged = bytearray(valid)
            damaged[rng.randrange(len(valid))] ^= 1 << rng.randrange(8)
            inputs.append(bytes(damaged))
    for data in inputs:
        if parser is rf.wav_info and data == BAD_WAV:
            continue  # Exact failing mutation is isolated below, not waived.
        parser(data)  # These public readers document None/empty on failure.


def test_ndef_fuzz_allows_only_exact_documented_valueerror():
    rng = random.Random(29)
    for data in [b'', b'\xff' * 128] + [NDEF[:i] for i in range(len(NDEF))] + [rng.randbytes(i) for i in range(100)]:
        try:
            rf.ndef_parse(data)
        except Exception as exc:
            assert type(exc) is ValueError  # never a UnicodeError/struct.error subclass


def test_oversized_text_fails_cleanly():
    data = SUB + b'x' * rf.MAX_TEXT
    for parser in (rf.flipper_parse, rf.sub_info, rf.nfc_info, rf.rfid_info, rf.ir_info):
        assert parser(data) is None


def test_invalid_iq_format_fails_cleanly():
    assert rf.iq_info(b'\0' * 16, 'invalid') is None


def test_zero_smoothing_fails_cleanly():
    assert rf.iq_pulses(b'\0' * 16, 'cs8', smooth=0) is None


def test_damaged_wave_chunk_fails_cleanly():
    assert rf.wav_info(BAD_WAV) is None
