"""Independent waveform and protocol locks; no RF devices or live requests.

Sources: ITU-R M.584-2 (POCSAG), ITU-R M.1371 (AIS field positions),
https://mode-s.org/1090mhz/content/ads-b/3-airborne-position.html,
https://mode-s.org/1090mhz/content/ads-b/2-identification.html.
CRC-16/IBM-SDLC check: 123456789 -> 906e (crccheck independent oracle).
"""
import io
import random
import struct
import wave

import numpy as np
import pytest
from crccheck.crc import Crc16IbmSdlc

import sdr_protocols as sdr


ADSB = bytes.fromhex('8D40621D58C382D690C8AC2863A7')
IDENT = bytes.fromhex('8D4840D6202CC371C32CE0576098')


def fsk_signal(bits, sps=16, rate=19200, deviation=2400):
    frequencies = np.repeat([deviation if b == '1' else -deviation for b in bits], sps)
    phase = np.concatenate(([0.0], np.cumsum(2 * np.pi * frequencies / rate)))
    return np.exp(1j * phase).tolist()


def reference_pocsag_word(data21):
    # Literal GF(2) long division, independent of every engine helper/constant.
    dividend = [int(b) for b in f'{data21:021b}'] + [0] * 10
    generator = [1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1]
    for offset in range(21):
        if dividend[offset]:
            for index, value in enumerate(generator):
                dividend[offset + index] ^= value
    parity_bits = int(''.join(map(str, dividend[-10:])), 2)
    word31 = (data21 << 10) | parity_bits
    return (word31 << 1) | (word31.bit_count() % 2)


def pocsag_frame(text='HELLO'):
    # Per M.584: chronological character bits are LSB first, then partitioned
    # into 20-bit codeword payloads without reversing the whole payload.
    message = ''.join(f'{ord(char):07b}'[::-1] for char in text)
    message += '0' * (-len(message) % 20)
    words = [reference_pocsag_word(((123456 >> 3) << 2) | 3)]
    words += [reference_pocsag_word(0x100000 | int(message[i:i + 20], 2))
              for i in range(0, len(message), 20)]
    return f'{0x7cd215d8:032b}' + ''.join(f'{word:032b}' for word in words) + f'{0x7a89c197:032b}'


def ais_payload():
    bits = list('0' * 168)
    for start, width, value in [(0, 6, 1), (8, 30, 123456789), (50, 10, 123),
                                (61, 28, -73500000), (89, 27, 28500000), (116, 12, 2345)]:
        bits[start:start + width] = f'{value % (1 << width):0{width}b}'
    return bytes(int(''.join(bits[i:i + 8]), 2) for i in range(0, 168, 8))


def ais_levels():
    payload = ais_payload()
    raw = payload + Crc16IbmSdlc.calc(payload).to_bytes(2, 'little')
    temporal = ''.join(f'{value:08b}'[::-1] for value in raw)
    stuffed, ones = '', 0
    for bit in temporal:
        stuffed += bit
        ones = ones + 1 if bit == '1' else 0
        if ones == 5:
            stuffed += '0'
            ones = 0
    level, output = 0, ''
    for bit in '01111110' + stuffed + '01111110':
        if bit == '0':
            level ^= 1
        output += str(level)
    return output


def wav_blob():
    stream = io.BytesIO()
    with wave.open(stream, 'wb') as out:
        out.setparams((2, 2, 8000, 0, 'NONE', 'not compressed'))
        out.writeframes(struct.pack('<hhhhhh', -32768, 16384, 0, -16384, 32767, 0))
    return stream.getvalue()


def test_synthesized_ook_ask_fsk_and_discriminator():
    bits = '1010011001011010'
    for low, high in [(0.0, 1.0), (0.25, 0.75)]:
        amplitudes = np.repeat([high if b == '1' else low for b in bits], 16)
        carrier = np.exp(1j * np.arange(len(amplitudes)) * 0.17)
        assert sdr.ook_bits((amplitudes * carrier).tolist(), 16) == bits
    iq = fsk_signal(bits)
    assert sdr.fsk_bits(iq, 19200, 1200) == bits
    assert sdr.fsk_bits(iq, 19200, 1200, invert=True) == bits.translate(str.maketrans('01', '10'))
    assert sdr.quadrature_discriminator(iq) == pytest.approx(np.repeat([np.pi / 4 if b == '1' else -np.pi / 4 for b in bits], 16))
    assert sdr.moving_average([2, 4, 8, 10], 2) == [2, 3, 6, 9]
    assert sdr.magnitude([3 + 4j, 5 + 12j]) == [5, 13]


def test_iq_and_wav_independent_pcm_layouts():
    assert sdr.load_iq(bytes([0, 255, 255, 0])) == [-1 + 1j, 1 - 1j]
    assert sdr.load_iq(struct.pack('<hhhh', -32768, 16384, 0, -16384), 'cs16le') == [-1 + .5j, -.5j]
    assert sdr.load_iq(struct.pack('<ffff', 1.25, -.5, 3, 4), 'cf32le') == [1.25 - .5j, 3 + 4j]
    assert sdr.load_wav(wav_blob(), channel=1) == ([.5, -.5, 0], 8000)


def test_published_adsb_and_ppm_waveform():
    result = sdr.parse_adsb_frame(ADSB)
    assert (result['df'], result['icao'], result['type_code']) == (17, '40621D', 11)
    assert (result['altitude_feet'], result['cpr_odd'], result['cpr_latitude'], result['cpr_longitude']) == (38000, False, 93000, 51372)
    assert sdr.modes_crc(ADSB) == 0
    assert sdr.parse_adsb_frame(IDENT)['callsign'] == 'KLM1023'
    waveform = [1.0 if i in (0, 2, 7, 9) else 0.0 for i in range(16)]
    for bit in ''.join(f'{byte:08b}' for byte in ADSB):
        waveform.extend([1.0, 0.0] if bit == '1' else [0.0, 1.0])
    decoded = sdr.decode_adsb_magnitude(np.repeat(waveform, 2).tolist(), samples_per_half=2)
    assert len(decoded) == 1
    assert decoded[0]['icao'] == '40621D'
    assert decoded[0]['altitude_feet'] == 38000
    assert decoded[0]['crc_ok'] is True


def test_pocsag_independent_bch_address_and_error_correction():
    word = reference_pocsag_word(((123456 >> 3) << 2) | 3)
    assert word == 0x0789182e
    assert sdr.correct_pocsag_codeword(word) == (0x0789182e, [])
    assert sdr.correct_pocsag_codeword(word ^ (1 << 7)) == (0x0789182e, [7])
    assert sdr.correct_pocsag_codeword(word ^ (1 << 3) ^ (1 << 29)) == (0x0789182e, [3, 29])
    message = sdr.decode_pocsag_bits(pocsag_frame())[0]
    assert (message['address'], message['function']) == (123456, 3)


def test_pocsag_alphanumeric_chronological_bit_order():
    assert sdr.decode_pocsag_bits(pocsag_frame())[0]['alphanumeric'] == 'HELLO'


def test_ais_known_fields_crc_nrzi_and_fsk():
    assert sdr.crc16_x25(b'123456789') == 0x906e
    payload = ais_payload()
    assert sdr.crc16_x25(payload) == Crc16IbmSdlc.calc(payload)
    direct = sdr.parse_ais_payload_bits(''.join(f'{byte:08b}' for byte in payload))
    frames = sdr.decode_ais_levels(ais_levels())
    assert len(frames) == 1
    for result in [direct, frames[0], sdr.decode_ais_iq(fsk_signal(ais_levels(), rate=153600, deviation=19200), 153600, gaussian_width=1)[0]]:
        assert result['message_type'] == 1
        assert result['mmsi'] == 123456789
        assert result['longitude'] == -122.5
        assert result['latitude'] == 47.5
        assert result['sog_knots'] == 12.3
        assert result['cog_degrees'] == 234.5
    assert frames[0]['crc_ok'] is True


def test_rds_biphase_known_levels_and_station_assembly():
    bits = '10100101'
    samples = [level for bit in bits for level in ([1] * 4 + [-1] * 4 if bit == '1' else [-1] * 4 + [1] * 4)]
    assert sdr.rds_biphase_bits(samples, 8) == bits
    groups = [{'pi': 0x1234, 'program_service_segment': (i, text)} for i, text in enumerate(['CS', 'CT', 'F ', 'FM'])]
    assert sdr.assemble_rds_groups(groups) == {'1234': {'program_service': 'CSCTF FM', 'radio_text': None}}


@pytest.mark.parametrize('entrypoint', [sdr.load_iq, sdr.load_wav, sdr.parse_adsb_frame, sdr.modes_crc])
def test_byte_parsers_random_truncation_mutations(entrypoint):
    rng = random.Random(0x534452)
    values = [b'', b'\xff' * 512] + [rng.randbytes(n) for n in range(32)]
    values += [wav_blob()[:n] for n in range(len(wav_blob()))]
    values += [ADSB[:n] for n in range(15)]
    for i in range(len(ADSB)):
        mutated = bytearray(ADSB)
        mutated[i] ^= 128
        values.append(bytes(mutated))
    for value in values:
        try:
            entrypoint(value)
        except sdr.SDRDecodeError:
            pass


@pytest.mark.parametrize('entrypoint', [sdr.decode_pocsag_bits, sdr.decode_ais_levels, sdr.decode_rds_bits])
def test_bit_parsers_fuzz_and_caps(entrypoint, monkeypatch):
    rng = random.Random(2026)
    for value in ['', 'x' * 168, '1' * 257, None] + [''.join(rng.choice('01') for _ in range(n)) for n in range(0, 300, 17)]:
        try:
            entrypoint(value)
        except sdr.SDRDecodeError:
            pass
    monkeypatch.setattr(sdr, 'MAX_BITS', 64)
    with pytest.raises(sdr.SDRDecodeError):
        entrypoint('0' * 65)


def test_explicit_small_byte_and_sample_caps(monkeypatch):
    monkeypatch.setattr(sdr, 'MAX_BYTES', 16)
    with pytest.raises(sdr.SDRDecodeError):
        sdr.load_iq(b'\0' * 18)
    with pytest.raises(sdr.SDRDecodeError):
        sdr.load_wav(wav_blob())
    monkeypatch.setattr(sdr, 'MAX_SAMPLES', 4)
    for function in [lambda: sdr.magnitude([0] * 5), lambda: sdr.ook_bits([0] * 5, 2),
                     lambda: sdr.quadrature_discriminator([0] * 5), lambda: sdr.decode_adsb_magnitude([0] * 5)]:
        with pytest.raises(sdr.SDRDecodeError):
            function()


def test_ais_field_parser_invalid_alphabet_declared_error():
    with pytest.raises(sdr.SDRDecodeError):
        sdr.parse_ais_payload_bits('x' * 168)


def test_fsk_rate_ratio_overflow_declared_error():
    with pytest.raises(sdr.SDRDecodeError):
        sdr.fsk_bits([], 1e308, 1e-308)
