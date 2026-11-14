"""Deterministic synthetic coverage for full saved-capture RF/GNSS chains."""
from __future__ import annotations

import cmath
import io
import json
import math
import struct
import sys
import wave
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import rf_demod_full as rf  # noqa: E402
import sdr_protocols as sdr  # noqa: E402


def fsk_iq(bits: str, *, rate: int, baud: int, deviation: float = 900.0) -> list[complex]:
    phase, values = 0.0, [1 + 0j]
    for bit in bits:
        step = 2 * math.pi * (deviation if bit == "1" else -deviation) / rate
        for _ in range(rate // baud):
            phase += step
            values.append(cmath.exp(1j * phase))
    return values


def test_gfsk_timing_tones_dc_and_pn9() -> None:
    bits = "00101111001010100110" * 3
    report = rf.gfsk_demodulate(fsk_iq(bits, rate=96000, baud=9600), 96000, 9600, matched_filter=False)
    assert report["bits"] == bits
    assert report["timing_offset"] == 0
    assert report["frequency_deviation_hz"] == pytest.approx(900.0, rel=0.03)
    assert report["eye_opening"] > 1.5
    centered = rf.remove_dc([3 + 2j, 5 + 4j])
    assert sum(centered) == 0j
    plain = b"CSCTF{whiten}\x00\xff"
    assert rf.pn9(rf.pn9(plain)) == plain
    with pytest.raises(rf.RFDemodError):
        rf.gfsk_demodulate([complex(float("nan"), 0)], 10, 2)


def lora_symbol(sf: int, symbol: int, *, samples_per_chip: int = 1, down: bool = False) -> list[complex]:
    chips = 1 << sf
    chirp = rf._lora_chirp(chips, down=down)
    base = [chirp[index] * cmath.exp(2j * math.pi * symbol * index / chips) for index in range(chips)]
    return [value for value in base for _ in range(samples_per_chip)]


def test_lora_oversampled_acquisition_preamble_and_cfo() -> None:
    sf, over, cfo = 5, 2, 5
    wanted = [11, 2, 19]
    capture = []
    capture += lora_symbol(sf, 21, samples_per_chip=over)
    for _ in range(8):
        capture += lora_symbol(sf, cfo, samples_per_chip=over)
    for symbol in wanted:
        capture += lora_symbol(sf, (symbol + cfo) % (1 << sf), samples_per_chip=over)
    assert rf.lora_symbol_bins(capture, sf, samples_per_chip=over) == [21] + [cfo] * 8 + [(value + cfo) % 32 for value in wanted]
    acquired = rf.acquire_lora(capture, sf, samples_per_chip=over, timing_offset=0)
    assert acquired["acquired"]
    assert acquired["preamble"] == {"start_symbol": 1, "length": 8, "frequency_offset_bins": cfo}
    assert acquired["corrected_symbols"][-3:] == wanted
    wrapped = rf.find_lora_preamble([31, 0, 31, 0, 31, 0, 8], sf, minimum=6, tolerance=1)
    assert wrapped is not None and wrapped["length"] == 6 and wrapped["frequency_offset_bins"] in (31, 0)
    assert rf.acquire_lora(lora_symbol(sf, 1) + lora_symbol(sf, 9), sf, timing_offset=0)["acquired"] is False
    sink = io.BytesIO()
    with wave.open(sink, "wb") as wav:
        wav.setnchannels(2); wav.setsampwidth(2); wav.setframerate(64_000)
        wav.writeframes(b"".join(struct.pack("<hh", round(value.real * 30000), round(value.imag * 30000)) for value in capture))
    wav_report = rf.decode_lora_wav(sink.getvalue(), sf, samples_per_chip=over, timing_offset=0)
    assert wav_report["corrected_symbols"][-3:] == wanted


def gray_encode(value: int) -> int:
    return value ^ (value >> 1)


def interleave(codewords: list[int], sf: int, cr: int) -> list[int]:
    assert len(codewords) == sf
    symbols = []
    for row in range(4 + cr):
        decoded = 0
        for column, codeword in enumerate(codewords):
            decoded |= ((codeword >> row) & 1) << ((column - row - 1) % sf)
        symbols.append(gray_encode(decoded))
    return symbols


def test_lora_diagonal_deinterleave_hamming_and_header() -> None:
    sf, cr = 5, 4
    nibbles = [1, 2, 3, 4, 5]
    codewords = [rf.lora_hamming_encode(value, cr) for value in nibbles]
    symbols = interleave(codewords, sf, cr)
    assert rf.lora_deinterleave(symbols, sf, cr) == codewords
    decoded = rf.decode_lora_codewords(symbols, sf, cr)
    assert decoded["nibbles"] == nibbles
    assert decoded["payload"] == b"!C"
    corrected = rf.lora_hamming_decode(codewords[2] ^ 0x40, cr)
    assert corrected == {"nibble": 3, "distance": 1, "corrected": True, "valid": True, "ambiguous": False}
    assert rf.parse_lora_explicit_header(bytes((12, 0x30, 0xA8))) == {
        "payload_length": 12, "coding_rate": 5, "payload_crc": True,
        "reserved": 0, "header_checksum": 21, "raw": "0c30a8",
    }
    with pytest.raises(rf.RFDemodError, match="incomplete"):
        rf.lora_deinterleave(symbols[:-1], sf, cr)


def pocsag_word(data21: int) -> int:
    value = data21 << 10
    value |= sdr._poly_remainder(value, 31, sdr.POCSAG_POLY, 10)
    word = value << 1
    return word | (word.bit_count() & 1)


def test_pocsag_rate_polarity_acquisition_and_bch_chain() -> None:
    address, function = 0x12340, 2
    address_word = pocsag_word(((address >> 3) << 2) | function)
    message_word = pocsag_word((1 << 20) | 0xABCDE)
    bits = f"{sdr.POCSAG_SYNC:032b}{address_word:032b}{message_word:032b}{sdr.POCSAG_IDLE:032b}"
    iq = fsk_iq(bits, rate=19200, baud=1200, deviation=1500)
    report = rf.acquire_pocsag(iq, 19200, baud_candidates=(512, 1200, 2400))
    assert report["acquired"] and report["baud"] == 1200 and report["sync_distance"] == 0
    assert report["messages"][0]["address"] == address
    inverted = fsk_iq(rf.bits_invert(bits), rate=19200, baud=1200, deviation=1500)
    assert rf.acquire_pocsag(inverted, 19200, baud_candidates=(1200,))["inverted"]
    sink = io.BytesIO()
    with wave.open(sink, "wb") as wav:
        wav.setnchannels(1); wav.setsampwidth(2); wav.setframerate(19200)
        wav.writeframes(b"".join(struct.pack("<h", 24000 if bit == "1" else -24000)
                                 for bit in bits for _ in range(16)))
    from_wav = rf.decode_pocsag_wav(sink.getvalue(), baud_candidates=(1200,))
    assert from_wav["acquired"] and from_wav["messages"][0]["address"] == address


def stuff(bits: str) -> str:
    output, ones = [], 0
    for bit in bits:
        output.append(bit)
        if bit == "1":
            ones += 1
            if ones == 5:
                output.append("0"); ones = 0
        else:
            ones = 0
    return "".join(output)


def nrzi_levels(decoded: str, initial: str = "0") -> str:
    level, output = initial, []
    for bit in decoded:
        if bit == "0":
            level = "1" if level == "0" else "0"
        output.append(level)
    return "".join(output)


def test_ais_gmsk_timing_nrzi_unstuff_crc_chain() -> None:
    mmsi = 123456789
    fields = f"{1:06b}{0:02b}{mmsi:030b}" + "0" * (168 - 38)
    payload = bytes(int(fields[offset:offset + 8], 2) for offset in range(0, 168, 8))
    fcs = sdr.crc16_x25(payload).to_bytes(2, "little")
    temporal = "".join(f"{byte:08b}"[::-1] for byte in payload + fcs)
    decoded = "01111110" + stuff(temporal) + "01111110"
    levels = nrzi_levels(decoded)
    report = rf.acquire_ais(fsk_iq(levels, rate=96000, baud=9600, deviation=2400), 96000)
    assert report["acquired"] and report["crc_valid_frames"] == 1
    assert report["frames"][0]["mmsi"] == mmsi


def test_gps_ca_gold_code_and_serial_acquisition() -> None:
    code = rf.gps_ca_code(1)
    assert len(code) == 1023 and sum(code) == -1
    assert sum(code[index] * code[(index + 1) % 1023] for index in range(1023)) == -1
    phase, doppler, rate = 137, 500.0, 1_023_000
    samples = [code[(index + phase) % 1023] * cmath.exp(2j * math.pi * doppler * index / rate)
               for index in range(1023)]
    reports = rf.acquire_gps_ca(samples, rate, (1, 2), doppler_bins=(-500.0, 0.0, 500.0))
    first = reports[0]
    assert first["acquired"] and first["doppler_hz"] == 500.0 and first["code_phase_samples"] == phase
    assert first["peak_ratio"] > 10
    assert reports[1]["peak_power"] < first["peak_power"] / 5
    with pytest.raises(rf.RFDemodError, match="one millisecond"):
        rf.acquire_gps_ca(samples[:100], rate, (1,))


def test_pseudorange_residuals_clock_bias_and_gnss_spoofing_evidence() -> None:
    residuals = rf.pseudorange_residuals([
        {"prn": 1, "satellite_ecef": [20_000_000, 0, 0], "pseudorange_m": 20_000_100},
        {"prn": 2, "satellite_ecef": [0, 20_000_000, 0], "pseudorange_m": 20_000_110},
        {"prn": 3, "satellite_ecef": [0, 0, 20_000_000], "pseudorange_m": 20_000_090},
    ], [0, 0, 0])
    assert residuals["clock_bias_m"] == 100
    assert residuals["rms_m"] == pytest.approx(math.sqrt(200 / 3))

    records = []
    for time, jump, position in ((0.0, 0.0, (0.0, 0.0)), (1.0, 2000.0, (1.0, 1.0))):
        for prn in range(1, 5):
            records.append({"time": time, "prn": prn, "pseudorange_m": 20_000_000 + prn * 100 + jump,
                            "doppler_hz": 0.0, "cn0_dbhz": 42.0,
                            "latitude": position[0], "longitude": position[1]})
    report = rf.analyze_gnss_measurements(records)
    kinds = {finding["kind"] for finding in report["findings"]}
    assert {"cn0-convergence", "common-code-phase-jump", "doppler-code-inconsistency", "impossible-position-jump"} <= kinds
    assert report["measurement_count"] == 8 and report["spoofing_indicators"] >= 3


def test_gnss_capture_json_csv_and_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    json_rows = rf.parse_gnss_capture(json.dumps({"measurements": [{"time": 1, "prn": 2}]}).encode())
    assert json_rows == [{"time": 1, "prn": 2}]
    csv_rows = rf.parse_gnss_capture(b"time,prn,pseudorange_m\n1,3,20000000\n")
    assert csv_rows == [{"time": 1.0, "prn": 3.0, "pseudorange_m": 20_000_000.0}]
    artifact = tmp_path / "gnss.json"
    artifact.write_text(json.dumps([{"time": 1, "prn": 2}]), encoding="utf-8")
    assert rf.main(["gnss", str(artifact)]) == 0
    assert json.loads(capsys.readouterr().out)["epoch_count"] == 1
    with pytest.raises(rf.RFDemodError):
        rf.parse_gnss_capture(b"{bad")
    monkeypatch.setattr(rf, "MAX_RECORDS", 1)
    with pytest.raises(rf.RFDemodError, match="record cap"):
        rf.parse_gnss_capture(b'[{"time":1,"prn":1},{"time":1,"prn":2}]')


def test_bounded_malformed_rf_inputs() -> None:
    with pytest.raises(rf.RFDemodError):
        rf.pn9(b"x", seed=0)
    with pytest.raises(rf.RFDemodError):
        rf.gps_ca_code(0)
    with pytest.raises(rf.RFDemodError):
        rf.lora_symbol_bins([], 13)
    with pytest.raises(rf.RFDemodError):
        rf.bits_invert("01?")
