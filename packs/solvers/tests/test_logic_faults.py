"""Deterministic saved-capture tests for logic_faults.py."""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import logic_faults as logic  # noqa: E402


def test_logic_csv_and_uart_with_parity():
    report = logic.parse_logic_csv("Time [s],CLK,DAT\n0,0,Low\n0.5,1,High\n")
    assert report["time"] == [0.0, 0.5]
    assert report["channels"] == {"CLK": [0, 1], "DAT": [0, 1]}

    sps, value = 8, 0xA5
    bits = [0] + [(value >> bit) & 1 for bit in range(8)]
    bits += [sum(bits[1:]) & 1, 1]  # even parity then stop
    levels = [1] * sps + [bit for bit in bits for _ in range(sps)] + [1] * sps
    rows = logic.decode_uart(levels, 8000, 1000, parity="even")
    assert rows == [{"sample": sps, "value": value, "data": bytes([value]),
                     "parity_bit": 0, "parity_ok": True, "framing_ok": True}]
    assert 900 <= logic.estimate_uart_baud(levels, 8000) <= 1100
    corrupted = levels.copy()
    corrupted[(1 + 1 + 8) * sps:(1 + 1 + 9) * sps] = [1] * sps  # parity bit
    corrupted[(1 + 1 + 9) * sps:(1 + 1 + 10) * sps] = [0] * sps  # stop bit
    bad = logic.decode_uart(corrupted, 8000, 1000, parity="even")[0]
    assert bad["parity_ok"] is False and bad["framing_ok"] is False


def _spi_trace(values: list[int], *, lsb: bool = False):
    clk, mosi, cs = [0], [0], [1]
    for value in values:
        cs.append(0); clk.append(0); mosi.append(0)
        order = range(8) if lsb else range(7, -1, -1)
        for bit in order:
            level = (value >> bit) & 1
            clk.extend((0, 1)); mosi.extend((level, level)); cs.extend((0, 0))
    clk.append(0); mosi.append(0); cs.append(1)
    return clk, mosi, cs


def test_spi_modes_bit_order_and_chip_select():
    clk, mosi, cs = _spi_trace([0x9F, 0xA5])
    rows = logic.decode_spi(clk, mosi=mosi, cs=cs)
    assert len(rows) == 1 and rows[0]["mosi"] == b"\x9f\xa5" and rows[0]["complete"]
    clk, mosi, cs = _spi_trace([0x53], lsb=True)
    assert logic.decode_spi(clk, mosi=mosi, cs=cs, bit_order="lsb")[0]["mosi"] == b"S"
    for mode in range(4):
        cpol = mode >> 1
        clock, data, select = [cpol, cpol], [0, 0], [1, 0]
        for bit in range(7, -1, -1):
            value = (0xA6 >> bit) & 1
            clock.extend((1 - cpol, cpol)); data.extend((value, value)); select.extend((0, 0))
        clock.append(cpol); data.append(0); select.append(1)
        assert logic.decode_spi(clock, mosi=data, cs=select, mode=mode)[0]["mosi"] == b"\xa6"


def _i2c_capture(octets: list[int]):
    scl, sda = [1], [1]
    def add(c, d):
        scl.append(c); sda.append(d)
    add(1, 0)  # START
    for byte in octets:
        for bit in range(7, -1, -1):
            value = (byte >> bit) & 1
            add(0, value); add(1, value); add(0, value)
        add(0, 0); add(1, 0); add(0, 0)  # ACK
    add(1, 0); add(1, 1)  # STOP
    return scl, sda


def test_i2c_address_ack_data_and_ten_bit_address():
    scl, sda = _i2c_capture([0xA0, 0x12, 0x34])
    rows = logic.decode_i2c(scl, sda)
    assert rows[0]["address"] == 0x50 and rows[0]["rw"] == "w"
    assert rows[0]["data"] == b"\x12\x34" and rows[0]["acks"] == [True] * 3
    scl, sda = _i2c_capture([0xF4, 0xAA, 0x01])
    row = logic.decode_i2c(scl, sda)[0]
    assert row["address_bits"] == 10 and row["address"] == 0x2AA and row["data"] == b"\x01"

    # A repeated START closes the first transaction without a STOP and labels the second.
    scl, sda = [1], [1]
    def add(c, d):
        scl.append(c); sda.append(d)
    def octet(value, ack):
        for bit in range(7, -1, -1):
            level = (value >> bit) & 1
            add(0, level); add(1, level); add(0, level)
        add(0, ack); add(1, ack); add(0, ack)
    add(1, 0); octet(0xA0, 0)
    add(0, 1); add(1, 1); add(1, 0)  # repeated START
    octet(0xA1, 1); add(1, 0); add(1, 1)
    repeated = logic.decode_i2c(scl, sda)
    assert not repeated[0]["stopped"] and repeated[1]["repeated_start"]
    assert repeated[1]["rw"] == "r" and repeated[1]["acks"] == [False]


def test_jtag_tap_ir_scan_and_swd_read_transfer():
    tck, tms, tdi, tdo = [0], [1], [0], [0]
    def cycle(ms, di, do=0):
        tck.extend((0, 1)); tms.extend((ms, ms)); tdi.extend((di, di)); tdo.extend((do, do))
    # reset->idle->selectDR->selectIR->captureIR->shiftIR
    for ms in (0, 1, 1, 0, 0):
        cycle(ms, 0)
    cycle(0, 1, 0); cycle(0, 0, 1); cycle(1, 1, 1)  # temporal LSB bits 101
    report = logic.decode_jtag(tck, tms, tdi, tdo)
    assert report["scans"][0]["kind"] == "IR"
    assert report["scans"][0]["tdi_bits"] == "101"
    assert report["scans"][0]["tdi_value"] == 5

    apndp, rnw, a2, a3 = 1, 1, 0, 1
    header = [1, apndp, rnw, a2, a3, apndp ^ rnw ^ a2 ^ a3, 0, 1]
    value = 0xA5C33C5A
    data = [(value >> bit) & 1 for bit in range(32)]
    stream = "".join(map(str, header + [0] + [1, 0, 0] + data + [sum(data) & 1]))
    row = logic.decode_swd_bits(stream)[0]
    assert row["port"] == "AP" and row["operation"] == "read" and row["address"] == 8
    assert row["ack"] == "OK" and row["data"] == value and row["data_parity_ok"]

    # A trace ending while SHIFT-DR still preserves an explicitly incomplete scan.
    tck, tms, tdi = [0], [1], [0]
    def dr_cycle(ms, di=0):
        tck.extend((0, 1)); tms.extend((ms, ms)); tdi.extend((di, di))
    for ms in (0, 1, 0, 0):  # idle, select-DR, capture-DR, shift-DR
        dr_cycle(ms)
    dr_cycle(0, 1)
    partial = logic.decode_jtag(tck, tms, tdi)["scans"][0]
    assert partial["kind"] == "DR" and partial["tdi_bits"] == "1" and not partial["complete"]

    write_header = [1, 0, 0, 1, 0, 1, 0, 1]  # valid DP write, address 4
    write_data = [(0x12345678 >> bit) & 1 for bit in range(32)]
    write_stream = "".join(map(str, write_header + [0] + [1, 0, 0] + [0] +
                                   write_data + [1 ^ (sum(write_data) & 1)]))
    write = logic.decode_swd_bits(write_stream)[0]
    assert write["operation"] == "write" and write["data"] == 0x12345678
    assert write["data_parity_ok"] is False
    wait_stream = "".join(map(str, header + [0] + [0, 1, 0]))
    assert logic.decode_swd_bits(wait_stream)[0]["ack"] == "WAIT"


def test_fault_diffs_glitch_grid_alignment_and_welch():
    diffs = logic.compare_faulty_outputs(b"\x00\xff", [b"\x01\xf0"])
    assert diffs[0]["changed_indices"] == [0, 1] and diffs[0]["hamming_distance"] == 5
    trials = [{"delay": 10, "width": 2, "outcome": "normal"},
              {"delay": 11, "width": 2, "outcome": "skip"},
              {"delay": 11, "width": 2, "outcome": "skip"}]
    summary = logic.analyze_glitch_trials(trials)
    assert summary["outcome_counts"] == {"normal": 1, "skip": 2}
    assert summary["parameter_cells"][1]["outcomes"] == {"skip": 2}

    aligned = logic.align_traces([[0, 0, 1, 2, 1, 0], [0, 1, 2, 1, 0, 0]], max_shift=2)
    assert aligned["shifts"] == [0, 1]
    values = logic.welch_t_trace([[0, 1], [0, 2], [0, 3]], [[0, 4], [0, 5], [0, 6]])
    assert values[0] == 0 and values[1] < 0


def test_aes_cpa_ranks_exact_synthetic_key_and_cli(tmp_path, capsys):
    key = 0x2B
    plaintexts = [bytes([value]) + bytes(15) for value in range(256)]
    traces = [[float(logic._AES_SBOX[plain[0] ^ key].bit_count()),
               float((plain[0] * 17) & 0xFF)] for plain in plaintexts]
    ranked = logic.cpa_aes_first_round(traces, plaintexts, top=3)
    assert ranked[0]["key"] == key and ranked[0]["sample"] == 0
    assert math.isclose(abs(ranked[0]["correlation"]), 1.0)

    fixture = tmp_path / "trials.json"
    fixture.write_text(json.dumps([{"delay": 1, "width": 2, "outcome": "ok"}]), encoding="utf-8")
    assert logic.main(["glitch", str(fixture)]) == 0
    assert json.loads(capsys.readouterr().out)["trial_count"] == 1


def test_malformed_capture_guards():
    with pytest.raises(logic.CaptureError):
        logic.decode_spi([0, 1], mosi=[0])
    with pytest.raises(logic.CaptureError):
        logic.decode_swd_bits("0102")
    with pytest.raises(logic.CaptureError, match="non-finite"):
        logic.align_traces([[0.0, math.nan], [0.0, 1.0]])
    with pytest.raises(logic.CaptureError, match="non-finite"):
        logic.welch_t_trace([[0.0], [math.inf]], [[0.0], [1.0]])
    old = logic.MAX_CPA_WORK
    logic.MAX_CPA_WORK = 1
    try:
        with pytest.raises(logic.CaptureError, match="work cap"):
            logic.cpa_aes_first_round([[0.0], [1.0], [2.0]], [bytes(16)] * 3)
    finally:
        logic.MAX_CPA_WORK = old
