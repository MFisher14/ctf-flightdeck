"""Independent RF vector locks. Signals are synthetic, never captured live.

PN9 bytes: TI DN509/SWRA322 Appendix Table 2, https://www.ti.com/lit/an/swra322/swra322.pdf.
Other protocol fixtures and their primary sources are in test_harden_rf_sdr_protocols.
"""
import io
import json
import random
import struct
import wave

import numpy as np
import pytest

import rf_demod_full as rf
from test_harden_rf_sdr_protocols import ais_levels, fsk_signal, pocsag_frame, wav_blob


def test_pn9_published_ti_dn509_check_values():
    # First five states' low octets, explicitly printed in TI's Appendix Table 2.
    assert rf.pn9(b'\0' * 5) == bytes.fromhex('ff e1 1d 9a ed')
    assert rf.pn9(bytes.fromhex('ff e1 1d 9a ed')) == bytes(5)
    # A nonzero payload lock cannot be satisfied by merely returning the key.
    assert rf.pn9(bytes.fromhex('00 01 02 03 04')) == bytes.fromhex('ff e0 1f 99 e9')


def test_synthetic_fsk_ask_and_dc_vectors():
    bits = '1010011001011010'
    result = rf.gfsk_demodulate(fsk_signal(bits), 19200, 1200, matched_filter=False, timing_offset=0)
    assert result['bits'] == bits
    assert result['frequency_deviation_hz'] == pytest.approx(2400)
    assert result['samples_per_symbol'] == 16
    assert rf.gfsk_demodulate(fsk_signal(bits), 19200, 1200, matched_filter=False, timing_offset=0, invert=True)['bits'] == '0101100110100101'
    levels = np.repeat([.8 if b == '1' else .2 for b in bits], 16).tolist()
    assert rf.level_demodulate(levels, 19200, 1200)['bits'] == bits
    assert rf.remove_dc([1 + 2j, 3 + 4j, 5 + 6j]) == [-2 - 2j, 0j, 2 + 2j]
    assert rf.fir_filter([1, 2, 3, 4], [.25, .5, .25]) == [1, 2, 3, 2.75]
    x = np.arange(-4, 5)
    sigma = np.sqrt(np.log(2)) * 8 / np.pi
    reference = np.exp(-.5 * (x / sigma) ** 2)
    assert rf.gaussian_kernel(8, .5, span=1) == pytest.approx(reference / reference.sum())


def test_wav_iq_and_lora_header_vectors():
    iq, rate = rf.load_stereo_iq_wav(wav_blob())
    assert iq == [-1 + .5j, -.5j, 32767 / 32768 + 0j]
    assert rate == 8000
    # Three documented deinterleaved header bytes: len, CR/CRC/reserved, checksum.
    assert rf.parse_lora_explicit_header(bytes.fromhex('2a 70 a0')) == {
        'payload_length': 42, 'coding_rate': 7, 'payload_crc': True,
        'reserved': 0, 'header_checksum': 20, 'raw': '2a70a0'}
    assert [rf.gray_decode(value) for value in [0, 1, 3, 2, 6, 7, 5, 4]] == list(range(8))
    assert rf.bits_invert('010110') == '101001'


def test_pocsag_and_ais_acquisition_known_addresses():
    pager = pocsag_frame()
    result = rf.acquire_pocsag(fsk_signal(pager), 19200, baud_candidates=(1200,))
    assert result['acquired'] is True
    assert result['messages'][0]['address'] == 123456
    assert result['messages'][0]['function'] == 3
    levels = np.repeat([1 if bit == '1' else -1 for bit in pager], 16).tolist()
    assert rf.acquire_pocsag_audio(levels, 19200, baud_candidates=(1200,))['messages'][0]['address'] == 123456
    ais = ais_levels()
    result = rf.acquire_ais(fsk_signal(ais, rate=153600, deviation=19200), 153600)
    assert result['crc_valid_frames'] == 1
    assert result['frames'][0]['mmsi'] == 123456789
    assert result['frames'][0]['longitude'] == -122.5
    levels = np.repeat([1 if bit == '1' else -1 for bit in ais], 16).tolist()
    assert rf.acquire_ais_audio(levels, 153600)['frames'][0]['latitude'] == 47.5


def test_gnss_json_csv_and_exact_geometric_residuals():
    records = [{'time': 100, 'prn': 1, 'pseudorange_m': 105.0}]
    assert rf.parse_gnss_capture(json.dumps({'measurements': records}).encode()) == records
    assert rf.parse_gnss_capture(b'time,prn,pseudorange_m\n100,1,105\n') == records
    result = rf.pseudorange_residuals([
        {'prn': 1, 'satellite_ecef': [3, 4, 0], 'pseudorange_m': 105},
        {'prn': 2, 'satellite_ecef': [0, 0, 12], 'pseudorange_m': 114},
    ], [0, 0, 0])
    assert result['clock_bias_m'] == 101
    assert [row['geometric_m'] for row in result['residuals']] == [5, 12]
    assert [row['residual_m'] for row in result['residuals']] == [-1, 1]
    assert result['rms_m'] == 1
    result = rf.analyze_gnss_measurements(records + records)
    assert result['measurement_count'] == 2 and result['epoch_count'] == 1
    assert result['findings'] == [{'kind': 'duplicate-satellite', 'severity': 'high', 'time': 100.0, 'prns': [1]}]


@pytest.mark.parametrize('entrypoint', [rf.pn9, rf.parse_lora_explicit_header, rf.parse_gnss_capture,
                                      rf.load_stereo_iq_wav, rf.decode_pocsag_wav, rf.decode_ais_wav])
def test_byte_entrypoints_fail_closed_mutations(entrypoint):
    rng = random.Random(0x5246)
    samples = [b'', b'\xff' * 128] + [rng.randbytes(n) for n in range(40)]
    samples += [wav_blob()[:n] for n in range(len(wav_blob()))]
    for source in [b'[{"time":1,"prn":2}]', bytes.fromhex('2a70a0')]:
        for n in range(len(source)):
            changed = bytearray(source)
            changed[n] ^= 128
            samples.append(bytes(changed))
    for sample in samples:
        try:
            entrypoint(sample)
        except rf.RFDemodError:
            pass


def test_small_input_sample_record_and_work_caps(monkeypatch):
    monkeypatch.setattr(rf, 'MAX_SAMPLES', 4)
    for function in [lambda: rf.remove_dc([0] * 5), lambda: rf.level_demodulate([0] * 5, 16000, 1000),
                     lambda: rf.gfsk_demodulate([0] * 5, 16000, 1000)]:
        with pytest.raises(rf.RFDemodError):
            function()
    monkeypatch.setattr(rf, 'MAX_BITS', 16)
    with pytest.raises(rf.RFDemodError):
        rf.pn9(b'\0' * 3)
    with pytest.raises(rf.RFDemodError):
        rf.bits_invert('0' * 17)
    monkeypatch.setattr(rf, 'MAX_RECORDS', 1)
    with pytest.raises(rf.RFDemodError):
        rf.parse_gnss_capture(b'[{},{}]')
    monkeypatch.setattr(rf, 'MAX_ACQUISITION_WORK', 4)
    with pytest.raises(rf.RFDemodError):
        rf.fir_filter([1, 2, 3], [1, 1])


def test_gnss_csv_oversized_field_declared_error():
    with pytest.raises(rf.RFDemodError):
        rf.parse_gnss_capture(b'column\n' + b'A' * 140000)


def test_gnss_nested_json_declared_error():
    with pytest.raises(rf.RFDemodError):
        rf.parse_gnss_capture(b'[' * 2000 + b'0' + b']' * 2000)


def test_gnss_bad_numeric_field_declared_error():
    with pytest.raises(rf.RFDemodError):
        rf.analyze_gnss_measurements([{'time': 'invalid', 'prn': 1}])


@pytest.mark.parametrize('entrypoint', [rf.gfsk_demodulate, rf.level_demodulate])
def test_demod_rate_ratio_overflow_declared_error(entrypoint):
    with pytest.raises(rf.RFDemodError):
        entrypoint([], 1e308, 1e-308)
