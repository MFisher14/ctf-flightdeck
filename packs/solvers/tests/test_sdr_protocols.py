"""Deterministic synthetic coverage for sdr_protocols.py."""
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


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import sdr_protocols as sdr  # noqa: E402


def test_iq_wav_ook_and_fsk_primitives():
    iq = sdr.load_iq(bytes([255, 128, 128, 0]), "cu8")
    assert len(iq) == 2 and iq[0].real > 0.99 and iq[1].imag < -0.99
    with pytest.raises(sdr.SDRDecodeError):
        sdr.load_iq(b"\x00", "cu8")

    sink = io.BytesIO()
    with wave.open(sink, "wb") as wav:
        wav.setnchannels(2); wav.setsampwidth(2); wav.setframerate(8000)
        wav.writeframes(b"".join(struct.pack("<hh", left, -left)
                                 for left in (-32767, 0, 16384, 32767)))
    samples, rate = sdr.load_wav(sink.getvalue(), channel=1)
    assert rate == 8000 and samples[0] > 0.99 and samples[2] == -0.5
    assert sdr.ook_bits([0.0] * 4 + [2.0] * 4 + [0.0] * 4, 4) == "010"

    bit_string, rate, baud = "00110101", 8000, 1000
    phase, capture = 0.0, []
    for bit in bit_string:
        step = 2 * math.pi * (800 if bit == "1" else -800) / rate
        for _ in range(rate // baud):
            phase += step
            capture.append(cmath.exp(1j * phase))
    # The discriminator has one fewer sample; one leading sample restores exact symbol alignment.
    capture.insert(0, 1 + 0j)
    assert sdr.fsk_bits(capture, rate, baud) == bit_string
    assert sdr.fsk_bits(capture, rate, baud, gaussian_width=3) == bit_string


def test_lora_dechirp_recovers_raw_bins():
    sf, count = 5, 32
    base = sdr._lora_upchirp(count)
    wanted = [0, 3, 17, 31]
    capture = []
    for symbol in wanted:
        capture.extend(base[k] * cmath.exp(2j * math.pi * symbol * k / count)
                       for k in range(count))
    assert sdr.lora_symbols(capture, sf) == wanted
    # SF12 previously exceeded a quadratic DFT cap; the radix-2 path handles it directly.
    large = sdr._lora_upchirp(1 << 12)
    assert sdr.lora_symbols(large, 12) == [0]
    with pytest.raises(sdr.SDRDecodeError):
        sdr.lora_symbols(capture, 4)


def _valid_modes_frame() -> bytes:
    prefix = bytes.fromhex("8dabcdef") + b"\x20\x10\x83\x04\x20\xc4\x10"
    parity = sdr.modes_crc(prefix + b"\x00\x00\x00").to_bytes(3, "big")
    frame = prefix + parity
    assert sdr.modes_crc(frame) == 0
    return frame


def test_adsb_crc_parse_and_ppm_demodulation():
    frame = _valid_modes_frame()
    parsed = sdr.parse_adsb_frame(frame)
    assert parsed["df"] == 17 and parsed["icao"] == "ABCDEF" and parsed["crc_ok"]

    magnitudes = [0.0] * 16
    for position in sdr._ADSB_PREAMBLE:
        magnitudes[position] = 10.0
    for byte in frame:
        for bit in range(7, -1, -1):
            magnitudes.extend((10.0, 0.0) if byte & (1 << bit) else (0.0, 10.0))
    reports = sdr.decode_adsb_magnitude(magnitudes)
    assert len(reports) == 1 and reports[0]["crc_ok"] and reports[0]["sample_offset"] == 0
    known = sdr.parse_adsb_frame(bytes.fromhex("8D4840D6202CC371C32CE0576098"))
    assert known["crc_ok"] and known["callsign"] == "KLM1023"

    # A short DF11 frame must decode without 112 bits of trailing capture.
    short_prefix = bytes.fromhex("58ABCDEF")
    short = short_prefix + sdr.modes_crc(short_prefix + b"\x00\x00\x00").to_bytes(3, "big")
    short_mag = [10.0 if slot in sdr._ADSB_PREAMBLE else 0.0 for slot in range(16)]
    for byte in short:
        for bit in range(7, -1, -1):
            short_mag.extend((10.0, 0.0) if byte & (1 << bit) else (0.0, 10.0))
    assert sdr.decode_adsb_magnitude(short_mag)[0]["length"] == 56
    with pytest.raises(sdr.SDRDecodeError):
        sdr.decode_adsb_magnitude([0.0, math.nan] * 100)


def _pocsag_word(data21: int) -> int:
    value = data21 << 10
    value |= sdr._poly_remainder(value, 31, sdr.POCSAG_POLY, 10)
    word = value << 1
    return word | (word.bit_count() & 1)


def test_pocsag_bch_correction_and_message_address():
    address, function = 0x12340, 2
    address_word = _pocsag_word(((address >> 3) << 2) | function)
    message_word = _pocsag_word((1 << 20) | 0xABCDE)
    corrected, positions = sdr.correct_pocsag_codeword(address_word ^ (1 << 7))
    assert corrected == address_word and positions == [7]
    bits = f"{sdr.POCSAG_SYNC:032b}{address_word ^ (1 << 7):032b}{message_word:032b}{sdr.POCSAG_IDLE:032b}"
    reports = sdr.decode_pocsag_bits(bits)
    assert reports[0]["address"] == address
    assert reports[0]["function"] == function
    assert reports[0]["corrected_bits"] == [7]
    corrected, positions = sdr.correct_pocsag_codeword(message_word ^ (1 << 3) ^ (1 << 29))
    assert corrected == message_word and positions == [3, 29]
    assert sdr.decode_pocsag_bits("0" * 256) == []


def _stuff(bits: str) -> str:
    out, ones = [], 0
    for bit in bits:
        out.append(bit)
        if bit == "1":
            ones += 1
            if ones == 5:
                out.append("0"); ones = 0
        else:
            ones = 0
    return "".join(out)


def _nrzi_levels(decoded: str, initial: str = "0") -> str:
    level, out = initial, []
    for bit in decoded:
        if bit == "0":
            level = "1" if level == "0" else "0"
        out.append(level)
    return "".join(out)


def test_ais_nrzi_unstuff_crc_and_fields():
    mmsi = 123456789
    fields = f"{1:06b}{0:02b}{mmsi:030b}" + "0" * (168 - 38)
    payload = bytes(int(fields[pos:pos + 8], 2) for pos in range(0, len(fields), 8))
    fcs = sdr.crc16_x25(payload).to_bytes(2, "little")
    temporal = "".join(f"{byte:08b}"[::-1] for byte in payload + fcs)
    decoded = "01111110" + _stuff(temporal) + "01111110"
    reports = sdr.decode_ais_levels(_nrzi_levels(decoded))
    assert len(reports) == 1 and reports[0]["crc_ok"]
    assert reports[0]["message_type"] == 1 and reports[0]["mmsi"] == mmsi
    damaged = bytearray(payload + fcs); damaged[0] ^= 1
    temporal = "".join(f"{byte:08b}"[::-1] for byte in damaged)
    bad = sdr.decode_ais_levels(_nrzi_levels("01111110" + _stuff(temporal) + "01111110"))
    assert bad and not bad[0]["crc_ok"]
    assert sdr._unstuff_hdlc("1111110") is None


def _rds_block(data: int, name: str) -> str:
    base = data << 10
    check = sdr._poly_remainder(base, 26, sdr.RDS_POLY, 10) ^ sdr.RDS_OFFSETS[name]
    block = base | check
    assert sdr.rds_syndrome(block) == sdr.RDS_OFFSETS[name]
    return f"{block:026b}"


def test_rds_group_sync_and_program_service_segment(tmp_path, capsys):
    # Group 0A, segment 0, characters "CS".
    bits = (_rds_block(0xC5F0, "A") + _rds_block(0x0000, "B") +
            _rds_block(0x1234, "C") + _rds_block(0x4353, "D"))
    reports = sdr.decode_rds_bits("101" + bits)
    assert reports[0]["offset"] == 3 and reports[0]["pi"] == 0xC5F0
    assert reports[0]["program_service_segment"] == (0, "CS")
    levels = [value for bit in "0101" for value in ((0.0, 0.0, 1.0, 1.0)
                                                     if bit == "0" else (1.0, 1.0, 0.0, 0.0))]
    assert sdr.rds_biphase_bits(levels, 4) == "0101"
    # Differential symbols 0,1,1,0 decode to payload 0,1,0,1 from previous zero.
    diff_levels = [value for bit in "0110" for value in ((0.0, 0.0, 1.0, 1.0)
                                                          if bit == "0" else (1.0, 1.0, 0.0, 0.0))]
    assert sdr.rds_biphase_bits(diff_levels, 4, differential=True) == "0101"
    assert sdr.rds_biphase_bits([0.0] * 4, 4) == "?"
    complete = [{"pi": 0xC5F0, "program_service_segment": (index, text)}
                for index, text in enumerate(("CS", "CT", "F2", "6!"))]
    assert sdr.assemble_rds_groups(complete)["C5F0"]["program_service"] == "CSCTF26!"

    fixture = tmp_path / "rds.bits"
    fixture.write_text(bits, encoding="ascii")
    assert sdr.main(["rds", str(fixture)]) == 0
    assert json.loads(capsys.readouterr().out)[0]["group_type"] == 0
